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
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;
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
    private final MetadataResolverConfigBuilder metadataResolverConfigBuilder;
    private ImmutableMap<String, MetadataResolverContainer> metadataResolvers = ImmutableMap.of();
    private List<JWK> trustAnchors = new ArrayList<>();
    private final Environment environment;
    private final EidasMetadataConfiguration eidasMetadataConfiguration;
    private final Timer timer;
    private final MetadataSignatureTrustEngineFactory metadataSignatureTrustEngineFactory;
    private long delayBeforeNextRefresh;

    @Inject
    public EidasMetadataResolverRepository(EidasTrustAnchorResolver trustAnchorResolver,
                                           Environment environment,
                                           EidasMetadataConfiguration eidasMetadataConfiguration,
                                           DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory,
                                           Timer timer,
                                           MetadataSignatureTrustEngineFactory metadataSignatureTrustEngineFactory,
                                           MetadataResolverConfigBuilder metadataResolverConfigBuilder) {
        this.trustAnchorResolver = trustAnchorResolver;
        this.environment = environment;
        this.eidasMetadataConfiguration = eidasMetadataConfiguration;
        this.dropwizardMetadataResolverFactory = dropwizardMetadataResolverFactory;
        this.timer = timer;
        this.metadataSignatureTrustEngineFactory = metadataSignatureTrustEngineFactory;
        this.metadataResolverConfigBuilder = metadataResolverConfigBuilder;
        refresh();
    }

    public Optional<MetadataResolver> getMetadataResolver(String entityId) {
        return Optional.ofNullable(metadataResolvers.get(entityId)).map(MetadataResolverContainer::getMetadataResolver);
    }

    public List<String> getEntityIdsWithResolver() {
        return metadataResolvers.keySet().asList();
    }

    public Optional<ExplicitKeySignatureTrustEngine> getSignatureTrustEngine(String entityId) {
        return Optional.ofNullable(metadataResolvers.get(entityId)).map(MetadataResolverContainer::getSignatureTrustEngine);
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
        ImmutableMap.Builder<String, MetadataResolverContainer> metadataResolverBuilder = ImmutableMap.builder();
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
        ImmutableMap<String, MetadataResolverContainer> oldMetadataResolvers = metadataResolvers;
        metadataResolvers = metadataResolverBuilder.build();
        stopOldMetadataResolvers(oldMetadataResolvers);
    }

    private MetadataResolverContainer createMetadataResolver(JWK trustAnchor) throws CertificateException, ComponentInitializationException, UnsupportedEncodingException {
        MetadataResolverConfiguration metadataResolverConfiguration = metadataResolverConfigBuilder.createMetadataResolverConfiguration(trustAnchor, eidasMetadataConfiguration);
        MetadataResolver metadataResolver = dropwizardMetadataResolverFactory.createMetadataResolver(environment, metadataResolverConfiguration);
        return new MetadataResolverContainer(
                metadataResolverConfiguration.getJerseyClientName(),
                metadataResolver,
                metadataSignatureTrustEngineFactory.createSignatureTrustEngine(metadataResolver));
    }

    private void stopOldMetadataResolvers(ImmutableMap<String, MetadataResolverContainer> oldMetadataResolvers) {
        oldMetadataResolvers.forEach((key, metadataResolverContainer) -> {
            MetadataResolver metadataResolver = metadataResolverContainer.getMetadataResolver();
            if (metadataResolver instanceof AbstractReloadingMetadataResolver) {
                // destroy() stops the timer - objects using the MetadataResolver will still be able to read metadata objects that are in memory
                ((AbstractReloadingMetadataResolver) metadataResolver).destroy();
            }
            environment.metrics().remove(metadataResolverContainer.getMetricName());
        });
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

    private class MetadataResolverContainer {
        private final String metricName;
        private final MetadataResolver metadataResolver;
        private final ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine;

        private MetadataResolverContainer(String metricName,
                                          MetadataResolver metadataResolver,
                                          ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine) {
            this.metricName = metricName;
            this.metadataResolver = metadataResolver;
            this.explicitKeySignatureTrustEngine = explicitKeySignatureTrustEngine;
        }

        private ExplicitKeySignatureTrustEngine getSignatureTrustEngine() {
            return explicitKeySignatureTrustEngine;
        }

        private MetadataResolver getMetadataResolver() {
            return metadataResolver;
        }

        private String getMetricName() {
            return metricName;
        }
    }
}
