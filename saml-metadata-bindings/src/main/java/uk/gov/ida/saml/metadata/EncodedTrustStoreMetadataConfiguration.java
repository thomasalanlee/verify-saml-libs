package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.util.Base64;

public class EncodedTrustStoreMetadataConfiguration extends MetadataConfiguration {

    @Valid
    @NotNull
    @JsonProperty
    private String trustStore;

    @Override
    public KeyStore getTrustStore() {
        return new KeyStoreLoader().load(new ByteArrayInputStream(Base64.getDecoder().decode(trustStore)), trustStorePassword);
    }
}
