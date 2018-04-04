package uk.gov.ida.saml.security;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.metadata.resolver.impl.BasicRoleDescriptorResolver;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.security.saml.TestCredentialFactory;

import java.io.IOException;
import java.net.URL;
import java.security.PublicKey;

import static org.assertj.core.api.Assertions.*;

public class MetadataBackedEncryptionCredentialResolverTest {
    private MetadataCredentialResolver metadataCredentialResolver;

    @Before
    public void beforeAll() throws Exception {
        InitializationService.initialize();

        StringBackedMetadataResolver metadataResolver = new StringBackedMetadataResolver(loadMetadata("metadata.xml"));
        BasicParserPool basicParserPool = new BasicParserPool();
        basicParserPool.initialize();
        metadataResolver.setParserPool(basicParserPool);
        metadataResolver.setRequireValidMetadata(true);
        metadataResolver.setId("arbitrary id");
        metadataResolver.initialize();

        BasicRoleDescriptorResolver basicRoleDescriptorResolver = new BasicRoleDescriptorResolver(metadataResolver);
        basicRoleDescriptorResolver.initialize();

        metadataCredentialResolver = new MetadataCredentialResolver();
        metadataCredentialResolver.setRoleDescriptorResolver(basicRoleDescriptorResolver);
        metadataCredentialResolver.setKeyInfoCredentialResolver(DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
        metadataCredentialResolver.initialize();
    }

    private String loadMetadata(String fileName) throws IOException {
        URL authnRequestUrl = getClass().getClassLoader().getResource(fileName);
        return Resources.toString(authnRequestUrl, Charsets.UTF_8);
    }

    @Test
    public void shouldSupportResolvingCredentialsFromKeysInMetadata() throws Exception {
        PublicKey publicKey = TestCredentialFactory.createPublicKey(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT);
        assertThat(new MetadataBackedEncryptionCredentialResolver(metadataCredentialResolver, SPSSODescriptor.DEFAULT_ELEMENT_NAME).getEncryptingCredential(TestEntityIds.HUB_ENTITY_ID).getPublicKey()).isEqualTo(publicKey);
    }

    @Test
    public void shouldFailToResolveIfEnttiyIsNotFound() throws Exception {
        assertThat(new MetadataBackedEncryptionCredentialResolver(metadataCredentialResolver, IDPSSODescriptor.DEFAULT_ELEMENT_NAME).getEncryptingCredential(TestEntityIds.HUB_ENTITY_ID)).isNull();
        assertThat(new MetadataBackedEncryptionCredentialResolver(metadataCredentialResolver, IDPSSODescriptor.DEFAULT_ELEMENT_NAME).getEncryptingCredential(TestEntityIds.STUB_IDP_ONE)).isNull();
    }

}