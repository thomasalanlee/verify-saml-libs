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
        metadataResource.stubFor(get(urlEqualTo("/metadata")).willReturn(aResponse().withBody(new MetadataFactory().defaultMetadata())));
    }

    @Deprecated
    public static final DropwizardAppRule<OldTestConfiguration> OLD_APPLICATION_DROPWIZARD_APP_RULE = new DropwizardAppRule<>(
            OldTestApplication.class,
            ResourceHelpers.resourceFilePath("old-test-app.yml"),
            ConfigOverride.config("metadata.uri", () -> "http://localhost:" + metadataResource.port() + "/metadata"),
            ConfigOverride.config("metadata.trustStorePath", () -> keyStoreRule.getAbsolutePath()),
            ConfigOverride.config("metadata.trustStorePassword", () -> keyStoreRule.getPassword()),
            ConfigOverride.config("metadata.trustStore.unknownProperty", () -> "unknownValue")
    );

    public static final DropwizardAppRule<TestConfiguration> APPLICATION_DROPWIZARD_APP_RULE = new DropwizardAppRule<>(
            TestApplication.class,
            ResourceHelpers.resourceFilePath("test-app.yml"),
            ConfigOverride.config("metadata.uri", () -> "http://localhost:" + metadataResource.port() + "/metadata"),
            ConfigOverride.config("metadata.trustStore.path", () -> keyStoreRule.getAbsolutePath()),
            ConfigOverride.config("metadata.trustStore.password", () -> keyStoreRule.getPassword()),
            ConfigOverride.config("metadata.unknownProperty", () -> "unknownValue")
    );

    @ClassRule
    @Deprecated
    public final static RuleChain oldRuleChain = RuleChain.outerRule(metadataResource).around(keyStoreRule).around(OLD_APPLICATION_DROPWIZARD_APP_RULE);

    @ClassRule
    public final static RuleChain ruleChain = RuleChain.outerRule(metadataResource).around(keyStoreRule).around(APPLICATION_DROPWIZARD_APP_RULE);

    @Deprecated
    private static Client oldClient;
    private static Client client;

    @BeforeClass
    public static void setUp() {
        oldClient = new JerseyClientBuilder(OLD_APPLICATION_DROPWIZARD_APP_RULE.getEnvironment()).build(SamlMetadataBundleTest.class.getName());
        client = new JerseyClientBuilder(APPLICATION_DROPWIZARD_APP_RULE.getEnvironment()).build(SamlMetadataBundleTest.class.getName());
    }

    @Test
    @Deprecated
    public void shouldReadMetadataFromMetadataServer() {
        Response response = oldClient.target("http://localhost:" + OLD_APPLICATION_DROPWIZARD_APP_RULE.getLocalPort() +"/foo").request().get();
        assertThat(response.readEntity(String.class)).isEqualTo(TestEntityIds.HUB_ENTITY_ID);
    }

    @Test
    public void shouldReadMetadataFromMetadataServerUsingTrustStoreBackedMetadataConfiguration() {
        Response response = client.target("http://localhost:" + APPLICATION_DROPWIZARD_APP_RULE.getLocalPort() +"/foo").request().get();
        assertThat(response.readEntity(String.class)).isEqualTo(TestEntityIds.HUB_ENTITY_ID);
    }

    @Deprecated
    public static class OldTestConfiguration extends Configuration {
        @JsonProperty("metadata")
        private TrustStorePathMetadataConfiguration metadataConfiguration;

        public MetadataResolverConfiguration getMetadataConfiguration() {
            return metadataConfiguration;
        }
    }

    public static class TestConfiguration extends Configuration {
        @JsonProperty("metadata")
        private TrustStoreBackedMetadataConfiguration metadataConfiguration;

        public MetadataResolverConfiguration getMetadataConfiguration() {
            return metadataConfiguration;
        }
    }

    @Deprecated
    public static class OldTestApplication extends Application<OldTestConfiguration> {
        private MetadataResolverBundle<OldTestConfiguration> bundle;

        @Override
        public void initialize(Bootstrap<OldTestConfiguration> bootstrap) {
            super.initialize(bootstrap);
            bundle = new MetadataResolverBundle<>(OldTestConfiguration::getMetadataConfiguration);
            bootstrap.addBundle(bundle);
        }

        @Override
        public void run(OldTestConfiguration configuration, Environment environment) {
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

    public static class TestApplication extends Application<TestConfiguration> {
        private MetadataResolverBundle<TestConfiguration> bundle;

        @Override
        public void initialize(Bootstrap<TestConfiguration> bootstrap) {
            super.initialize(bootstrap);
            bundle = new MetadataResolverBundle<>(TestConfiguration::getMetadataConfiguration);
            bootstrap.addBundle(bundle);
        }

        @Override
        public void run(TestConfiguration configuration, Environment environment) {
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
