package uk.gov.ida.saml.metadata.factories;

import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.client.JerseyClientConfiguration;
import io.dropwizard.setup.Environment;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import uk.gov.ida.saml.metadata.MetadataConfiguration;

import javax.ws.rs.client.Client;
import java.net.ProxySelector;

public class MetadataClientFactory {
    public Client getClient(Environment environment, MetadataConfiguration metadataConfiguration) {
        JerseyClientConfiguration jerseyClientConfiguration = metadataConfiguration.getJerseyClientConfiguration();
        JerseyClientBuilder jerseyClientBuilder = new JerseyClientBuilder(environment)
                .using(jerseyClientConfiguration);
        if (null == jerseyClientConfiguration.getProxyConfiguration()) {
            // If proxy config is not specified use system route planner
            // this allows use of the jvm proxy properties specified here
            // https://docs.oracle.com/javase//docs/technotes/guides/net/proxies.html
            jerseyClientBuilder.using(new SystemDefaultRoutePlanner(ProxySelector.getDefault()));
        }

        return jerseyClientBuilder.build(metadataConfiguration.getJerseyClientName());
    }
}
