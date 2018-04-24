package uk.gov.ida.saml.metadata;

import io.dropwizard.client.JerseyClientConfiguration;

import java.net.URI;
import java.security.KeyStore;

public interface MetadataResolverConfiguration {

    KeyStore getTrustStore();

    KeyStore getHubTrustStore();

    KeyStore getIdpTrustStore();

    URI getUri();

    Long getMinRefreshDelay();

    Long getMaxRefreshDelay();

    String getExpectedEntityId();

    JerseyClientConfiguration getJerseyClientConfiguration();

    String getJerseyClientName();

    String getHubFederationId();
}
