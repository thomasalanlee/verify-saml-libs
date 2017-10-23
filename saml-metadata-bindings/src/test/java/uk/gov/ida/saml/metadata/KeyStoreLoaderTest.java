package uk.gov.ida.saml.metadata;

import helpers.ResourceHelpers;
import keystore.KeyStoreRule;
import keystore.builders.KeyStoreRuleBuilder;
import org.junit.ClassRule;
import org.junit.Test;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.metadata.exception.EmptyTrustStoreException;

import java.security.KeyStore;
import java.security.KeyStoreException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.*;

public class KeyStoreLoaderTest {
    private KeyStoreLoader keyStoreLoader = new KeyStoreLoader();

    @ClassRule
    public static KeyStoreRule emptyKeyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().build();

    @ClassRule
    public static KeyStoreRule keyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().withCertificate("hub", TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT).build();

    @Test
    public void testLoadFromString() throws Exception {
        KeyStore keyStore = keyStoreLoader.load(ResourceHelpers.resourceFilePath("test-truststore.ts"), "puppet");
        assertNotNull(keyStore);
    }

    @Test
    public void testLoadFromStream() throws Exception {
        KeyStore keyStore = keyStoreLoader.load(this.getClass().getResourceAsStream("/test-truststore.ts"), "puppet");
        assertNotNull(keyStore);
    }

    @Test(expected = EmptyTrustStoreException.class)
    public void shouldThrowExceptionIfKeyStoreContainsNoCertificates() throws KeyStoreException {
        keyStoreLoader.load(emptyKeyStoreRule.getAbsolutePath(), emptyKeyStoreRule.getPassword());
    }

    @Test(expected = RuntimeException.class)
    public void shouldPropagateExceptionIfKeystoreIsUninitialized() throws KeyStoreException {
        keyStoreLoader.validate(KeyStore.getInstance(KeyStore.getDefaultType()));
    }

    @Test
    public void shouldReturnKeyStoreContainingCertificates() throws KeyStoreException {
        assertThat(keyStoreLoader.load(keyStoreRule.getAbsolutePath(), keyStoreRule.getPassword()).containsAlias("hub")).isTrue();
    }
}
