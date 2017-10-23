package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.dropwizard.client.JerseyClientConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.security.KeyStore;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "type",
        defaultImpl = FileBackedTrustStoreMetadataConfiguration.class)
@JsonSubTypes({
        @JsonSubTypes.Type(value=FileBackedTrustStoreMetadataConfiguration.class, name="file"),
        @JsonSubTypes.Type(value=EncodedTrustStoreMetadataConfiguration.class, name="encoded")
})
public abstract class MetadataConfiguration {

    @NotNull
    @Valid
    @JsonProperty
    protected String trustStorePassword;

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

    public abstract KeyStore getTrustStore();

    public URI getUri() {
        return uri;
    }

    public Long getMinRefreshDelay() {
        return minRefreshDelay;
    }

    public Long getMaxRefreshDelay() {
        return maxRefreshDelay;
    }

    public String getExpectedEntityId() {
        return expectedEntityId;
    }

    public JerseyClientConfiguration getJerseyClientConfiguration() {
        return client;
    }

    public String getJerseyClientName() {
        return jerseyClientName;
    }
}
