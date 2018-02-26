package uk.gov.ida.saml.metadata;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;
import io.dropwizard.setup.Environment;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;

import javax.inject.Inject;
import javax.ws.rs.core.UriBuilder;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class EidasMetadataResolverRepository {

    private final Logger log = LoggerFactory.getLogger(EidasMetadataResolverRepository.class);
    private final EidasTrustAnchorResolver trustAnchorResolver;
    private final DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory = new DropwizardMetadataResolverFactory();
    private HashMap<String, MetadataResolver> metadataResolvers = new HashMap<>();
    private final Environment environment;
    private final EidasMetadataConfiguration eidasMetadataConfiguration;
    private Timer timer = new Timer();
    private long delayBeforeNextRefresh;

    @Inject
    public EidasMetadataResolverRepository(EidasTrustAnchorResolver trustAnchorResolver, Environment environment, EidasMetadataConfiguration eidasMetadataConfiguration) {
        this.trustAnchorResolver = trustAnchorResolver;
        this.environment = environment;
        this.eidasMetadataConfiguration = eidasMetadataConfiguration;

        refresh();
    }

    public MetadataResolver getMetadataResolver(String entityId) {
        return metadataResolvers.get(entityId);
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
            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    refresh();
                }
            }, delayBeforeNextRefresh);
        }
    }

    private void registerMetadataResolvers(List<JWK> trustAnchors) {
        for(JWK trustAnchor : trustAnchors) {
            try {
                X509Certificate certificate = X509CertUtils.parse(Base64.decode(String.valueOf(trustAnchor.getX509CertChain().get(0))));
                certificate.checkValidity();

                addMetadataResolver(trustAnchor);
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

        registerHealthCheck(metadataResolver, trustAnchor.getKeyID());
    }

    private void registerHealthCheck(MetadataResolver metadataResolver, String entityId) {
        environment.healthChecks().register(getHealthCheckName(entityId), new MetadataHealthCheck(metadataResolver, entityId));
    }

    private String getHealthCheckName(String entityId) {
        return "eIDAS metadata: " + entityId;
    }

    private MetadataResolverConfiguration createMetadataResolverConfiguration(JWK jwk) throws UnsupportedEncodingException {
        URI metadataUri = UriBuilder.fromUri(eidasMetadataConfiguration.getMetadataBaseUri()).path(URLEncoder.encode(jwk.getKeyID(), "UTF-8")).build();

        return new TrustStoreBackedMetadataConfiguration(
                metadataUri,
                eidasMetadataConfiguration.getMinRefreshDelay(),
                eidasMetadataConfiguration.getMaxRefreshDelay(),
                null,
                eidasMetadataConfiguration.getJerseyClientConfiguration(),
                eidasMetadataConfiguration.getJerseyClientName(),
                null,
                new DynamicTrustStoreConfiguration(jwk.getKeyStore())
                );
    }

    private void removeMetadataResolvers(List<JWK> trustAnchors) {
        for(String entityId : metadataResolvers.keySet()) {
            if(trustAnchors.stream().noneMatch(jwk -> jwk.getKeyID().equals(entityId))) {
                metadataResolvers.remove(entityId);
                environment.healthChecks().unregister(getHealthCheckName(entityId));
            }
        }
    }
}
