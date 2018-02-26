package uk.gov.ida.saml.metadata;

import io.dropwizard.client.JerseyClientConfiguration;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Optional;

public class EidasMetadataConfiguration {
    public EidasMetadataConfiguration(URI trustAnchorUri,
                                      Long minRefreshDelay,
                                      Long maxRefreshDelay,
                                      Long trustAnchorMaxRefreshDelay,
                                      JerseyClientConfiguration client,
                                      String jerseyClientName,
                                      X509Certificate signingCertificate,
                                      URI metadataBaseUri)
    {
        this.trustAnchorUri = trustAnchorUri;
        this.minRefreshDelay = Optional.ofNullable(minRefreshDelay).orElse(60000L);
        this.maxRefreshDelay = Optional.ofNullable(maxRefreshDelay).orElse(600000L);
        this.trustAnchorMinRefreshDelay = Optional.ofNullable(trustAnchorMaxRefreshDelay).orElse(60000L);
        this.trustAnchorMaxRefreshDelay = Optional.ofNullable(trustAnchorMaxRefreshDelay).orElse(3600000l);
        this.client = Optional.ofNullable(client).orElse(new JerseyClientConfiguration());
        this.jerseyClientName = Optional.ofNullable(jerseyClientName).orElse("MetadataClient");
        this.signingCertificate = signingCertificate;
        this.metadataBaseUri = metadataBaseUri;
    }

    private URI trustAnchorUri;

    /* Used to set {@link org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider#minRefreshDelay} */
    private Long minRefreshDelay;

    /* Used to set {@link org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider#maxRefreshDelay} */
    private Long maxRefreshDelay;

    private Long trustAnchorMaxRefreshDelay;

    private Long trustAnchorMinRefreshDelay;

    private JerseyClientConfiguration client;

    private String jerseyClientName;

    private X509Certificate signingCertificate;

    private URI metadataBaseUri;

    public URI getTrustAnchorUri() {
        return trustAnchorUri;
    }

    public Long getMinRefreshDelay() {
        return minRefreshDelay;
    }

    public Long getMaxRefreshDelay() {
        return maxRefreshDelay;
    }

    public Long getTrustAnchorMaxRefreshDelay() {
        return trustAnchorMaxRefreshDelay;
    }

    public Long getTrustAnchorMinRefreshDelay() {
        return trustAnchorMinRefreshDelay;
    }

    public JerseyClientConfiguration getJerseyClientConfiguration() {
        return client;
    }

    public String getJerseyClientName() {
        return jerseyClientName;
    }

    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    public URI getMetadataBaseUri() {
        return metadataBaseUri;
    }
}
