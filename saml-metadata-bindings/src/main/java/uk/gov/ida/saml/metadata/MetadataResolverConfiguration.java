package uk.gov.ida.saml.metadata;

import io.dropwizard.client.JerseyClientConfiguration;

import java.net.URI;

public interface MetadataResolverConfiguration {

    public String getTrustStorePath();

    public String getTrustStorePassword();

    public URI getUri();

    public Long getMinRefreshDelay();

    public Long getMaxRefreshDelay();

    public String getExpectedEntityId();

    public JerseyClientConfiguration getJerseyClientConfiguration();

    public String getJerseyClientName();
}
