package uk.gov.ida.saml.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.google.common.io.Resources;
import keystore.KeyStoreRule;
import keystore.builders.KeyStoreRuleBuilder;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.nio.file.Files;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.saml.core.test.TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT;

public class TrustStoreConfigurationTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private ObjectMapper objectMapper = new ObjectMapper();

    @ClassRule
    public static KeyStoreRule keyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().withCertificate("hub", HUB_TEST_PUBLIC_SIGNING_CERT).build();

    @Test
    public void should_loadTrustStoreFromFile() throws Exception {
        String jsonConfig = "{\"type\": \"file\", \"trustStorePath\": \"" + keyStoreRule.getAbsolutePath() + "\", \"trustStorePassword\": \"" + keyStoreRule.getPassword() + "\"}";
        TrustStoreConfiguration config = objectMapper.readValue(jsonConfig, TrustStoreConfiguration.class);

        assertThat(config.getTrustStore()).isNotNull();
    }

    @Test
    public void should_loadTrustStoreFromEncodedString() throws Exception {
        byte[] trustStore = Files.readAllBytes(new File(keyStoreRule.getAbsolutePath()).toPath());
        String encodedTrustStore = Base64.getEncoder().encodeToString(trustStore);
        String jsonConfig = "{\"type\": \"encoded\", \"trustStore\": \"" + encodedTrustStore + "\", \"trustStorePassword\": \"" + keyStoreRule.getPassword() + "\"}";
        TrustStoreConfiguration config = objectMapper.readValue(jsonConfig, TrustStoreConfiguration.class);

        assertThat(config.getTrustStore()).isNotNull();
    }

    @Test
    public void should_defaultToFileBackedWhenNoTypeProvided() throws Exception {
        String jsonConfig = "{\"trustStorePath\": \"" + keyStoreRule.getAbsolutePath() + "\", \"trustStorePassword\": \"" + keyStoreRule.getPassword() + "\"}";
        TrustStoreConfiguration config = objectMapper.readValue(jsonConfig, TrustStoreConfiguration.class);

        assertThat(config.getTrustStore()).isNotNull();
    }

    @Test
    public void should_loadTrustStoreFromFileUsingAliases() throws Exception {
        String jsonConfig = "{\"path\": \"" + keyStoreRule.getAbsolutePath() + "\", \"password\": \"" + keyStoreRule.getPassword() + "\"}";
        TrustStoreConfiguration config = objectMapper.readValue(jsonConfig, TrustStoreConfiguration.class);

        assertThat(config.getTrustStore()).isNotNull();
    }

    @Test(expected = UnrecognizedPropertyException.class)
    public void should_ThrowExceptionWhenIncorrectKeySpecified() throws Exception {
        String jsonConfig = "{\"type\": \"file\", \"trustStorePathhhh\": \"path\", \"trustStorePassword\": \"puppet\"}";
        objectMapper.readValue(jsonConfig, TrustStoreConfiguration.class);
    }
}