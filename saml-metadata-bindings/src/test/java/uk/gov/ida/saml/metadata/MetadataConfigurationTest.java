package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.Resources;
import keystore.KeyStoreRule;
import keystore.builders.KeyStoreRuleBuilder;
import org.junit.ClassRule;
import org.junit.Test;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import java.io.File;
import java.nio.file.Files;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class MetadataConfigurationTest {

    private ObjectMapper objectMapper = new ObjectMapper();

    @ClassRule
    public static KeyStoreRule keyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().withCertificate("hub", TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT).build();

    @Test
    public void should_loadMetadataConfigurationWithFile() throws Exception {
        String jsonConfig = "{\"type\": \"file\", \"trustStorePath\": \"" + keyStoreRule.getAbsolutePath() + "\", \"trustStorePassword\": \"" + keyStoreRule.getPassword() + "\"}";
        MetadataConfiguration config = objectMapper.readValue(jsonConfig, MetadataConfiguration.class);

        assertThat(config.getTrustStore().containsAlias("hub")).isTrue();
    }

    @Test
    public void should_loadMetadataConfigurationWithEncoded() throws Exception {
        byte[] cert = Files.readAllBytes(new File(keyStoreRule.getAbsolutePath()).toPath());
        String encodedCert = Base64.getEncoder().encodeToString(cert);
        String jsonConfig = "{\"type\": \"encoded\", \"trustStore\": \"" + encodedCert + "\", \"trustStorePassword\": \"" + keyStoreRule.getPassword() + "\"}";
        MetadataConfiguration config = objectMapper.readValue(jsonConfig, MetadataConfiguration.class);

        assertThat(config.getTrustStore().containsAlias("hub")).isTrue();
    }

    @Test
    public void should_defaultToFile() throws Exception {
        String jsonConfig = "{\"trustStorePath\": \"" + keyStoreRule.getAbsolutePath() + "\", \"trustStorePassword\": \"" + keyStoreRule.getPassword() + "\"}";
        MetadataConfiguration config = objectMapper.readValue(jsonConfig, MetadataConfiguration.class);

        assertThat(config.getTrustStore().containsAlias("hub")).isTrue();
    }

}