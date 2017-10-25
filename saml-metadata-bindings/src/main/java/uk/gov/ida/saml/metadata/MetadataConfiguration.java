package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.client.JerseyClientConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.net.URI;

public class MetadataConfiguration implements MetadataResolverConfiguration {
    protected MetadataConfiguration() {
    }

    public MetadataConfiguration(String trustStorePath, String trustStorePassword, URI uri, Long minRefreshDelay, Long maxRefreshDelay, String expectedEntityId, JerseyClientConfiguration client, String jerseyClientName) {
        this.trustStorePath = trustStorePath;
        this.trustStorePassword = trustStorePassword;
        this.uri = uri;
        this.minRefreshDelay = minRefreshDelay;
        this.maxRefreshDelay = maxRefreshDelay;
        this.expectedEntityId = expectedEntityId;
        this.client = client;
        this.jerseyClientName = jerseyClientName;
    }

    /*
     * TrustStore configuration is used to do certificate chain validation when loading metadata
     */
    @NotNull
    @Valid
    @JsonProperty
    private String trustStorePath;

    @NotNull
    @Valid
    @JsonProperty
    private String trustStorePassword;

    /* HTTP{S} URL the SAML metadata can be loaded from */
    @NotNull
    @Valid
    @JsonProperty
    private URI uri;

    /* Used to set {@link org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider#minRefreshDelay} */
    @Valid
    @NotNull
    @JsonProperty
    private Long minRefreshDelay;

    /* Used to set {@link org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider#maxRefreshDelay} */
    @Valid
    @NotNull
    @JsonProperty
    private Long maxRefreshDelay;

    /*
    * What entityId can be expected to reliably appear in the SAML metadata?
    * Used to provide a healthcheck {@link uk.gov.ida.saml.dropwizard.metadata.MetadataHealthCheck}
    */
    @NotNull
    @Valid
    @JsonProperty
    private String expectedEntityId;

    @NotNull
    @Valid
    @JsonProperty
    private JerseyClientConfiguration client;

    @NotNull
    @Valid
    @JsonProperty
    private String jerseyClientName = "MetadataClient";

    @Override
    public String getTrustStorePath() {
        return trustStorePath;
    }

    @Override
    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    @Override
    public URI getUri() {
        return uri;
    }

    @Override
    public Long getMinRefreshDelay() {
        return minRefreshDelay;
    }

    @Override
    public Long getMaxRefreshDelay() {
        return maxRefreshDelay;
    }

    @Override
    public String getExpectedEntityId() {
        return expectedEntityId;
    }

    @Override
    public JerseyClientConfiguration getJerseyClientConfiguration() {
        return client;
    }

    @Override
    public String getJerseyClientName() {
        return jerseyClientName;
    }
}
