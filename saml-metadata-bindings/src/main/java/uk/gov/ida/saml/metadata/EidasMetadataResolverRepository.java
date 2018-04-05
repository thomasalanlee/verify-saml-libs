package uk.gov.ida.saml.metadata;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;
import io.dropwizard.setup.Environment;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.trustanchor.CountryTrustAnchor;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;
import uk.gov.ida.saml.metadata.factories.MetadataSignatureTrustEngineFactory;

import javax.inject.Inject;
import javax.ws.rs.core.UriBuilder;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;
import java.util.stream.Collectors;

public class EidasMetadataResolverRepository {

    private final Logger log = LoggerFactory.getLogger(EidasMetadataResolverRepository.class);
    private final EidasTrustAnchorResolver trustAnchorResolver;
    private final DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory;
    private ImmutableMap<String, MetadataPair> metadataResolvers = ImmutableMap.of();
    private List<JWK> trustAnchors = new ArrayList<>();
    private final Environment environment;
    private final EidasMetadataConfiguration eidasMetadataConfiguration;
    private final Timer timer;
    private MetadataSignatureTrustEngineFactory metadataSignatureTrustEngineFactory;
    private long delayBeforeNextRefresh;

    @Inject
    public EidasMetadataResolverRepository(EidasTrustAnchorResolver trustAnchorResolver,
                                           Environment environment,
                                           EidasMetadataConfiguration eidasMetadataConfiguration,
                                           DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory,
                                           Timer timer,
                                           MetadataSignatureTrustEngineFactory metadataSignatureTrustEngineFactory) {
        this.trustAnchorResolver = trustAnchorResolver;
        this.environment = environment;
        this.eidasMetadataConfiguration = eidasMetadataConfiguration;
        this.dropwizardMetadataResolverFactory = dropwizardMetadataResolverFactory;
        this.timer = timer;
        this.metadataSignatureTrustEngineFactory = metadataSignatureTrustEngineFactory;
        refresh();
    }

    public MetadataResolver getMetadataResolver(String entityId) {
        return Optional.ofNullable(metadataResolvers.get(entityId)).map(MetadataPair::getMetadataResolver).orElse(null);
    }

    public List<String> getEntityIdsWithResolver() {
        return metadataResolvers.keySet().asList();
    }

    public ExplicitKeySignatureTrustEngine getSignatureTrustEngine(String entityId) {
        return Optional.ofNullable(metadataResolvers.get(entityId)).map(MetadataPair::getSignatureTrustEngine).orElse(null);
    }

    public Map<String, MetadataResolver> getMetadataResolvers(){
        return metadataResolvers.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> e.getValue().getMetadataResolver()
                ));
    }

    public List<String> getTrustAnchorsEntityIds() {
        return trustAnchors.stream().map(JWK::getKeyID).collect(Collectors.toList());
    }

    public void refresh() {
        delayBeforeNextRefresh = eidasMetadataConfiguration.getTrustAnchorMaxRefreshDelay();
        try {
            trustAnchors = trustAnchorResolver.getTrustAnchors();
            refreshMetadataResolvers(trustAnchors);
        } catch (Exception e) {
            log.error("Error fetching trust anchor or validating it", e);
            setShortRefreshDelay();
        } finally {
            timer.schedule(new RefreshTimerTask(), delayBeforeNextRefresh);
        }
    }

    private void refreshMetadataResolvers(List<JWK> trustAnchors) {
        ImmutableMap.Builder<String, MetadataPair> metadataResolverBuilder = ImmutableMap.builder();
        for (JWK trustAnchor : trustAnchors) {
            try {
                X509Certificate certificate = X509CertUtils.parse(Base64.decode(String.valueOf(trustAnchor.getX509CertChain().get(0))));
                certificate.checkValidity();

                Collection<String> errors = CountryTrustAnchor.findErrors(trustAnchor);
                if (!errors.isEmpty()) {
                    throw new Error(String.format("Managed to generate an invalid anchor: %s", String.join(", ", errors)));
                }

                metadataResolverBuilder.put(trustAnchor.getKeyID(), createMetadataResolver(trustAnchor));

                Date metadataSigningCertExpiryDate = certificate.getNotAfter();
                Date nextRunTime = DateTime.now().plus(delayBeforeNextRefresh).toDate();
                if (metadataSigningCertExpiryDate.before(nextRunTime)) {
                    setShortRefreshDelay();
                }
            } catch (Exception e) {
                log.error("Error creating MetadataResolver for " + trustAnchor.getKeyID(), e);
            }
        }
        ImmutableMap<String, MetadataPair> oldMetadataResolvers = metadataResolvers;
        metadataResolvers = metadataResolverBuilder.build();
        stopOldMetadataResolvers(oldMetadataResolvers);
    }

    private MetadataPair createMetadataResolver(JWK trustAnchor) throws CertificateException, ComponentInitializationException {
        MetadataResolver metadataResolver = dropwizardMetadataResolverFactory.createMetadataResolver(environment, createMetadataResolverConfiguration(trustAnchor));
        return new MetadataPair(metadataResolver, metadataSignatureTrustEngineFactory.createSignatureTrustEngine(metadataResolver));
    }

    private MetadataResolverConfiguration createMetadataResolverConfiguration(JWK trustAnchor) throws CertificateException {
        URI metadataUri = UriBuilder.fromUri(trustAnchor.getKeyID())
                .build();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> trustedCertChain = trustAnchor.getX509CertChain()
                .stream()
                .map(base64 -> base64.decode())
                .map(ByteArrayInputStream::new)
                .map(certStream -> {
                    try { //Java streams don't allow throwing checked exceptions
                        return (X509Certificate) certificateFactory.generateCertificate(certStream);
                    } catch (CertificateException e) {
                        throw new RuntimeException("Certificate in Trust Anchor x5c is not a valid x509", e);
                    }
                })
                .collect(Collectors.toList());

        return new TrustStoreBackedMetadataConfiguration(
                metadataUri,
                eidasMetadataConfiguration.getMinRefreshDelay(),
                eidasMetadataConfiguration.getMaxRefreshDelay(),
                null,
                eidasMetadataConfiguration.getJerseyClientConfiguration(),
                getClientName(trustAnchor.getKeyID()),
                null,
                new DynamicTrustStoreConfiguration(buildKeyStoreFromCertificate(trustedCertChain))
                );
    }

    private void stopOldMetadataResolvers(ImmutableMap<String, MetadataPair> oldMetadataResolvers) {
        oldMetadataResolvers.forEach((key, metadataPair) -> {
            MetadataResolver metadataResolver = metadataPair.getMetadataResolver();
            if (metadataResolver instanceof AbstractReloadingMetadataResolver) {
                //destroy() stops the timer - objects using the MetadataResolver will still be able to read metadata objects that are in memory
                ((AbstractReloadingMetadataResolver) metadataResolver).destroy();
            }
            environment.metrics().remove(getClientName(key));
        });
    }

    private KeyStore buildKeyStoreFromCertificate(List<X509Certificate> certificates) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            for(X509Certificate certificate : certificates) {
                keyStore.setCertificateEntry("certificate-" + certificates.indexOf(certificate), certificate);
            }
            return keyStore;
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String getClientName(String entityId) {
        return String.format("%s - %s", eidasMetadataConfiguration.getJerseyClientName(), entityId);
    }

    private class RefreshTimerTask extends TimerTask {
        @Override
        public void run() {
            refresh();
        }
    }

    private void setShortRefreshDelay() {
        delayBeforeNextRefresh = eidasMetadataConfiguration.getTrustAnchorMinRefreshDelay();
    }

    private class MetadataPair {
        private final MetadataResolver metadataResolver;
        private final ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine;

        private MetadataPair(MetadataResolver metadataResolver, ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine) {
            this.metadataResolver = metadataResolver;
            this.explicitKeySignatureTrustEngine = explicitKeySignatureTrustEngine;
        }

        ExplicitKeySignatureTrustEngine getSignatureTrustEngine() {
            return explicitKeySignatureTrustEngine;
        }

        private MetadataResolver getMetadataResolver() {
            return metadataResolver;
        }
    }
}
