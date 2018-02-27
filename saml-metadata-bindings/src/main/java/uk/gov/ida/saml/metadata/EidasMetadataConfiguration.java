package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.client.JerseyClientConfiguration;

import java.net.URI;
import java.util.Optional;

public class EidasMetadataConfiguration {

    @JsonCreator
    public EidasMetadataConfiguration(@JsonProperty("trustAnchorUri") URI trustAnchorUri,
                                      @JsonProperty("minRefreshDelay") Long minRefreshDelay,
                                      @JsonProperty("maxRefreshDelay") Long maxRefreshDelay,
                                      @JsonProperty("trustAnchorMaxRefreshDelay") Long trustAnchorMaxRefreshDelay,
                                      @JsonProperty("trustAnchorMinRefreshDelay") Long trustAnchorMinRefreshDelay,
                                      @JsonProperty("client") JerseyClientConfiguration client,
                                      @JsonProperty("jerseyClientName") String jerseyClientName,
                                      @JsonProperty("trustStore") TrustStoreConfiguration trustStore,
                                      @JsonProperty("metadataBaseUri") URI metadataBaseUri)
    {
        this.trustAnchorUri = trustAnchorUri;
        this.minRefreshDelay = Optional.ofNullable(minRefreshDelay).orElse(60000L);
        this.maxRefreshDelay = Optional.ofNullable(maxRefreshDelay).orElse(600000L);
        this.trustAnchorMinRefreshDelay = Optional.ofNullable(trustAnchorMinRefreshDelay).orElse(60000L);
        this.trustAnchorMaxRefreshDelay = Optional.ofNullable(trustAnchorMaxRefreshDelay).orElse(3600000L);
        this.client = Optional.ofNullable(client).orElse(new JerseyClientConfiguration());
        this.jerseyClientName = Optional.ofNullable(jerseyClientName).orElse("MetadataClient");
        this.trustStore = trustStore;
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

    private URI metadataBaseUri;

    private TrustStoreConfiguration trustStore;

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

    public URI getMetadataBaseUri() {
        return metadataBaseUri;
    }

    public TrustStoreConfiguration getTrustStoreConfiguration() {
        return trustStore;
    }
}
