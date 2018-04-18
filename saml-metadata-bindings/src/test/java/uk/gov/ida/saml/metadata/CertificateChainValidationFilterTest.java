package uk.gov.ida.saml.metadata;

import certificates.values.CACertificates;
import keystore.KeyStoreRule;
import keystore.builders.KeyStoreRuleBuilder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.io.IOUtils;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;
import uk.gov.ida.common.shared.security.verification.PKIXParametersProvider;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.saml.metadata.Role.SP;
import static uk.gov.ida.saml.metadata.Role.IDP;

@RunWith(OpenSAMLMockitoRunner.class)
public class CertificateChainValidationFilterTest {

    private static final List<String> IDP_ENTITY_IDS = asList(TestEntityIds.STUB_IDP_ONE, TestEntityIds.STUB_IDP_TWO, TestEntityIds.STUB_IDP_THREE, TestEntityIds.STUB_IDP_FOUR);
    private static final List<String> HUB_ENTITY_IDS = Collections.singletonList(TestEntityIds.HUB_ENTITY_ID);

    @ClassRule
    public static KeyStoreRule idpKeyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().withCertificate("idp", CACertificates.TEST_IDP_CA)
                                                                    .withCertificate("root", CACertificates.TEST_ROOT_CA).build();

    @ClassRule
    public static KeyStoreRule hubKeyStoreRule = KeyStoreRuleBuilder.aKeyStoreRule().withCertificate("hub", CACertificates.TEST_CORE_CA)
                                                                    .withCertificate("root", CACertificates.TEST_ROOT_CA).build();

    private MetadataFactory metadataFactory = new MetadataFactory();
    private CertificateChainValidator certificateChainValidator = new CertificateChainValidator(new PKIXParametersProvider(), new X509CertificateFactory());
    private CertificateChainValidationFilter certificateChainValidationFilter;

    @Test
    public void shouldNotFilterOutTrustedCertificatesWhenAllAreValid() throws Exception {
        certificateChainValidationFilter = new CertificateChainValidationFilter(IDP, certificateChainValidator, idpKeyStoreRule.getKeyStore());

        final XMLObject metadata = validateMetadata(metadataFactory.defaultMetadata());

        assertThat(getEntityIdsFromMetadata(metadata, SP)).containsOnlyElementsOf(HUB_ENTITY_IDS);
        assertThat(getEntityIdsFromMetadata(metadata, IDP)).containsOnlyElementsOf(IDP_ENTITY_IDS);
    }

    @Test
    public void shouldFilterOutUntrustedCertificatesWhenCertificatesAreNotSignedByCorrectCA() throws Exception {
        certificateChainValidationFilter = new CertificateChainValidationFilter(IDP, certificateChainValidator, hubKeyStoreRule.getKeyStore());

        final XMLObject metadata = validateMetadata(metadataFactory.defaultMetadata());

        assertThat(getEntityIdsFromMetadata(metadata, IDP)).isEmpty();
        assertThat(getEntityIdsFromMetadata(metadata, SP)).containsOnlyElementsOf(HUB_ENTITY_IDS);
    }

    private XMLObject validateMetadata(String metadataContent) throws XMLParserException, UnmarshallingException, ComponentInitializationException {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.initialize();
        XMLObject metadata = XMLObjectSupport.unmarshallFromInputStream(parserPool, IOUtils.toInputStream(metadataContent));
        return certificateChainValidationFilter.filter(metadata);
    }

    private List<String> getEntityIdsFromMetadata(final XMLObject metadata, final Role role) {
        final EntitiesDescriptor entitiesDescriptor = (EntitiesDescriptor) metadata;

        List<String> entityIds = new ArrayList<>();

        entitiesDescriptor.getEntityDescriptors().forEach(
        entityDescriptor -> {
            final String entityID = entityDescriptor.getEntityID();
            entityDescriptor.getRoleDescriptors()
                            .stream()
                            .filter(roleDescriptor -> roleDescriptor.getElementQName().equals(role.getRoleDescriptor()))
                            .map(roleDescriptor -> entityID)
                            .forEach(entityIds::add);
        });
        return entityIds;
    }
}
