package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.security.KeyStore;

public class TrustStoreBackedMetadataConfiguration extends MetadataConfiguration {

    @NotNull
    @Valid
    @JsonProperty
    private TrustStoreConfiguration trustStore;

    @Override
    public KeyStore getTrustStore() {
        return trustStore.getTrustStore();
    }
}
