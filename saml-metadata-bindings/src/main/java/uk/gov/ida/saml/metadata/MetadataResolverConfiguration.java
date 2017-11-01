package uk.gov.ida.saml.metadata;

import io.dropwizard.client.JerseyClientConfiguration;

import java.net.URI;
import java.security.KeyStore;

public interface MetadataResolverConfiguration {

    public KeyStore getTrustStore();

    public URI getUri();

    public Long getMinRefreshDelay();

    public Long getMaxRefreshDelay();

    public String getExpectedEntityId();

    public JerseyClientConfiguration getJerseyClientConfiguration();

    public String getJerseyClientName();

    public String getHubFederationId();
}
