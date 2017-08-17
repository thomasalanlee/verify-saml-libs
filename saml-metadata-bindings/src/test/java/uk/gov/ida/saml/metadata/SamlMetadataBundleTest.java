package uk.gov.ida.saml.metadata;

import certificates.values.CACertificates;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import io.dropwizard.Application;
import io.dropwizard.Configuration;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit.DropwizardAppRule;
import keystore.KeyStoreRule;
import keystore.builders.KeyStoreRuleBuilder;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.saml.core.IdaSamlBootstrap;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.metadata.bundle.MetadataResolverBundle;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.Response;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

public class SamlMetadataBundleTest {
    public static final WireMockRule metadataResource = new WireMockRule(WireMockConfiguration.options().dynamicPort());

    public static KeyStoreRule keyStoreRule = new KeyStoreRuleBuilder().withCertificate("metadata", CACertificates.TEST_METADATA_CA).withCertificate("root", CACertificates.TEST_ROOT_CA).build();

    static {
        IdaSamlBootstrap.bootstrap();
        metadataResource.stubFor(get(urlEqualTo("/metadata")).willReturn(aResponse().withBody(new MetadataFactory().defaultMetadata())));
    }

    public static final DropwizardAppRule<TestConfiguration> applicationDropwizardAppRule = new DropwizardAppRule<>(
            TestApplication.class,
            ResourceHelpers.resourceFilePath("test-app.yml"),
            ConfigOverride.config("metadata.uri", () -> "http://localhost:" + metadataResource.port() + "/metadata"),
            ConfigOverride.config("metadata.trustStorePath", () -> keyStoreRule.getAbsolutePath()),
            ConfigOverride.config("metadata.trustStorePassword", () -> keyStoreRule.getPassword())
    );

    @ClassRule
    public final static RuleChain ruleChain = RuleChain.outerRule(metadataResource).around(keyStoreRule).around(applicationDropwizardAppRule);

    private static Client client;

    @BeforeClass
    public static void setUp() throws Exception {
      client = new JerseyClientBuilder(applicationDropwizardAppRule.getEnvironment()).build(SamlMetadataBundleTest.class.getName());
    }

    @Test
    public void shouldReadMetadataFromMetadataServer() throws Exception {
        Response response = client.target("http://localhost:" + applicationDropwizardAppRule.getLocalPort() +"/foo").request().get();
        assertThat(response.readEntity(String.class)).isEqualTo(TestEntityIds.HUB_ENTITY_ID);
    }

    public static class TestConfiguration extends Configuration {
        @JsonProperty("metadata")
        MetadataConfiguration metadataConfiguration;

        public MetadataConfiguration getMetadataConfiguration() {
            return metadataConfiguration;
        }
    }

    public static class TestApplication extends Application<TestConfiguration> {
        private MetadataResolverBundle<TestConfiguration> bundle;

        @Override
        public void initialize(Bootstrap<TestConfiguration> bootstrap) {
            super.initialize(bootstrap);
            bundle = new MetadataResolverBundle<>(TestConfiguration::getMetadataConfiguration);
            bootstrap.addBundle(bundle);
        }

        @Override
        public void run(TestConfiguration configuration, Environment environment) throws Exception {
            environment.jersey().register(new TestResource(bundle.getMetadataResolver()));
        }

        @Path("/")
        public static class TestResource {
            private MetadataResolver metadataResolver;
            TestResource(MetadataResolver metadataResolver) {
                this.metadataResolver = metadataResolver;
            }

            @Path("/foo")
            @GET
            public String getMetadata() throws ResolverException {
                return metadataResolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(TestEntityIds.HUB_ENTITY_ID))).getEntityID();
            };
        }
    }

}
