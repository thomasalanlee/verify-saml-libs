package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.client.JerseyClientConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.security.KeyStore;

public class FileBackedTrustStoreMetadataConfiguration extends MetadataConfiguration {

    @NotNull
    @Valid
    @JsonProperty
    private String trustStorePath;


    @Override
    public KeyStore getTrustStore() {
        return new KeyStoreLoader().load(trustStorePath, trustStorePassword);
    }
}
