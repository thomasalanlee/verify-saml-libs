package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.client.JerseyClientConfiguration;
import uk.gov.ida.saml.metadata.factories.MetadataTrustStoreProvider;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.security.KeyStore;

/**
 * Uses a flat structure to parse metadata details
 *
 * @deprecated Use {@link TrustStoreBackedMetadataConfiguration} instead. This will change configs
 * to use a nested trust store object instead of having path and password as part of the metadata configuration.
 */
@Deprecated
public class TrustStorePathMetadataConfiguration extends MetadataConfiguration {
    protected TrustStorePathMetadataConfiguration() {
    }

    public TrustStorePathMetadataConfiguration(String trustStorePath, String trustStorePassword, URI uri, Long minRefreshDelay, Long maxRefreshDelay, String expectedEntityId, JerseyClientConfiguration client, String jerseyClientName) {
        this.trustStorePath = trustStorePath;
        this.trustStorePassword = trustStorePassword;
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

    @Override
    public KeyStore getTrustStore() {
        return new MetadataTrustStoreProvider(new KeyStoreLoader(), trustStorePath, trustStorePassword).get();
    }
}
