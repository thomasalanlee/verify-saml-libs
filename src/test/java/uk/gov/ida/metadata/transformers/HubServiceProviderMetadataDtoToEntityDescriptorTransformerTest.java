package uk.gov.ida.metadata.transformers;

import org.joda.time.DateTime;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.credential.UsageType;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.saml.core.api.CoreTransformersFactory;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.metadata.domain.AssertionConsumerServiceEndpointDto;
import uk.gov.ida.saml.metadata.domain.ContactPersonDto;
import uk.gov.ida.saml.metadata.domain.HubServiceProviderMetadataDto;
import uk.gov.ida.saml.metadata.domain.OrganisationDto;
import uk.gov.ida.saml.metadata.transformers.HubServiceProviderMetadataDtoToEntityDescriptorTransformer;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.saml.core.test.builders.CertificateBuilder.aCertificate;
import static uk.gov.ida.saml.core.test.builders.OrganisationDtoBuilder.anOrganisationDto;

@RunWith(OpenSAMLMockitoRunner.class)
public class HubServiceProviderMetadataDtoToEntityDescriptorTransformerTest {

    @Test
    public void shouldAddAllSigningCertificiatesToEntityDescriptor() throws Exception {
        OrganisationDto organisationDto = anOrganisationDto().build();
        Certificate primaryCertificiate = aCertificate().withIssuerId("primaryCert").withCertificate(TestCertificateStrings.TEST_PUBLIC_CERT).build();
        Certificate secondaryCertificate = aCertificate().withIssuerId("secondaryCert").withCertificate(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT).build();
        List<Certificate> hubSigningCertificates = Arrays.asList(primaryCertificiate, secondaryCertificate);

        HubServiceProviderMetadataDto hubServiceProviderMetadataDto = new HubServiceProviderMetadataDto(
                "http://hub.gov.uk",
                DateTime.now().plusHours(1),
                organisationDto, Collections.<ContactPersonDto>emptyList(),
                hubSigningCertificates,
                Collections.<Certificate>emptyList(),
                Collections.<AssertionConsumerServiceEndpointDto>emptyList());

        HubServiceProviderMetadataDtoToEntityDescriptorTransformer transformer = new CoreTransformersFactory().getHubServiceProviderMetadataDtoToEntityDescriptorTransformer();

        EntityDescriptor entityDescriptor = transformer.apply(hubServiceProviderMetadataDto);

        assertThat(entityDescriptor.getRoleDescriptors()).hasSize(1);

        RoleDescriptor roleDescriptor = entityDescriptor.getRoleDescriptors().get(0);
        assertThat(roleDescriptor.getKeyDescriptors()).hasSize(2);

        KeyDescriptor primaryKeyDescriptor = roleDescriptor.getKeyDescriptors().get(0);
        assertThat(primaryKeyDescriptor.getUse()).isEqualTo(UsageType.SIGNING);
        assertThat(primaryKeyDescriptor.getKeyInfo().getKeyNames().get(0).getValue()).isEqualTo("primaryCert");
        assertThat(primaryKeyDescriptor.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue()).isEqualTo(TestCertificateStrings.TEST_PUBLIC_CERT);

        KeyDescriptor secondaryKeyDescriptor = roleDescriptor.getKeyDescriptors().get(1);
        assertThat(secondaryKeyDescriptor.getUse()).isEqualTo(UsageType.SIGNING);
        assertThat(secondaryKeyDescriptor.getKeyInfo().getKeyNames().get(0).getValue()).isEqualTo("secondaryCert");
        assertThat(secondaryKeyDescriptor.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue()).isEqualTo(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT);
    }
}
