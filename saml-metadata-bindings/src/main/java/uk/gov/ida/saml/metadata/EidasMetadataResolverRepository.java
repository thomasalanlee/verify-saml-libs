package uk.gov.ida.saml.metadata;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;
import io.dropwizard.setup.Environment;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.trustanchor.CountryTrustAnchor;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;

import javax.inject.Inject;
import javax.ws.rs.core.UriBuilder;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class EidasMetadataResolverRepository {

    private final Logger log = LoggerFactory.getLogger(EidasMetadataResolverRepository.class);
    private final EidasTrustAnchorResolver trustAnchorResolver;
    private final DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory;
    private HashMap<String, MetadataResolver> metadataResolvers = new HashMap<>();
    private final Environment environment;
    private final EidasMetadataConfiguration eidasMetadataConfiguration;
    private final Timer timer;
    private long delayBeforeNextRefresh;

    @Inject
    public EidasMetadataResolverRepository(EidasTrustAnchorResolver trustAnchorResolver, Environment environment, EidasMetadataConfiguration eidasMetadataConfiguration, DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory, Timer timer) {
        this.trustAnchorResolver = trustAnchorResolver;
        this.environment = environment;
        this.eidasMetadataConfiguration = eidasMetadataConfiguration;
        this.dropwizardMetadataResolverFactory = dropwizardMetadataResolverFactory;
        this.timer = timer;

        refresh();
    }

    public MetadataResolver getMetadataResolver(String entityId) {
        return metadataResolvers.get(entityId);
    }

    public HashMap<String, MetadataResolver> getMetadataResolvers(){
        return metadataResolvers;
    }

    private void refresh() {
        delayBeforeNextRefresh =  eidasMetadataConfiguration.getTrustAnchorMaxRefreshDelay();
        try {
            List<JWK> trustAnchors = trustAnchorResolver.getTrustAnchors();

            removeMetadataResolvers(trustAnchors);
            registerMetadataResolvers(trustAnchors);
        } catch (Exception e) {
            log.error("Error fetching trust anchor or validating it", e);
            delayBeforeNextRefresh = eidasMetadataConfiguration.getTrustAnchorMinRefreshDelay();
        } finally {
            timer.schedule(new RefreshTimerTask(), delayBeforeNextRefresh);
        }
    }

    private void registerMetadataResolvers(List<JWK> trustAnchors) {
        for(JWK trustAnchor : trustAnchors) {
            try {
                X509Certificate certificate = X509CertUtils.parse(Base64.decode(String.valueOf(trustAnchor.getX509CertChain().get(0))));
                certificate.checkValidity();

                addMetadataResolver(trustAnchor);
                Collection<String> errors = CountryTrustAnchor.findErrors(trustAnchor);
                if (!errors.isEmpty()) {
                    throw new Error(String.format("Managed to generate an invalid anchor: %s", String.join(", ", errors)));
                }

                Date metadataSigningCertExpiryDate = certificate.getNotAfter();
                Date nextRunTime = DateTime.now().plus(delayBeforeNextRefresh).toDate();
                if(metadataSigningCertExpiryDate.before(nextRunTime)) {
                    delayBeforeNextRefresh = eidasMetadataConfiguration.getTrustAnchorMinRefreshDelay();
                }
            } catch (Exception e) {
                log.error("Error creating MetadataResolver for " + trustAnchor.getKeyID(), e);
            }
        }
    }

    private void addMetadataResolver(JWK trustAnchor) throws UnsupportedEncodingException {
        MetadataResolver metadataResolver = dropwizardMetadataResolverFactory.createMetadataResolver(environment, createMetadataResolverConfiguration(trustAnchor));
        metadataResolvers.put(trustAnchor.getKeyID(), metadataResolver);
    }

    private MetadataResolverConfiguration createMetadataResolverConfiguration(JWK trustAnchor) throws UnsupportedEncodingException {
        URI metadataUri = UriBuilder.fromUri(eidasMetadataConfiguration.getMetadataBaseUri()).path(URLEncoder.encode(trustAnchor.getKeyID(), "UTF-8")).build();

        return new TrustStoreBackedMetadataConfiguration(
                metadataUri,
                eidasMetadataConfiguration.getMinRefreshDelay(),
                eidasMetadataConfiguration.getMaxRefreshDelay(),
                null,
                eidasMetadataConfiguration.getJerseyClientConfiguration(),
                eidasMetadataConfiguration.getJerseyClientName(),
                null,
                new DynamicTrustStoreConfiguration(trustAnchor.getKeyStore())
                );
    }

    private void removeMetadataResolvers(List<JWK> trustAnchors) {
        for(String entityId : metadataResolvers.keySet()) {
            if(trustAnchors.stream().noneMatch(jwk -> jwk.getKeyID().equals(entityId))) {
                if (metadataResolvers.get(entityId) instanceof AbstractReloadingMetadataResolver){
                    ((AbstractReloadingMetadataResolver) metadataResolvers.get(entityId)).destroy();
                }
                metadataResolvers.remove(entityId);
            }
        }
    }

    private class RefreshTimerTask extends TimerTask {
        @Override
        public void run() {
            refresh();
        }
    }
}
