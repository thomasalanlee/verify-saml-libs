package uk.gov.ida.metadata.transformers;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.test.OpenSAMLRunner;
import uk.gov.ida.saml.metadata.domain.OrganisationDto;
import uk.gov.ida.saml.metadata.transformers.OrganizationUnmarshaller;

import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.saml.core.test.builders.OrganisationDtoBuilder.anOrganisationDto;

@RunWith(OpenSAMLRunner.class)
public class OrganizationUnmarshallerTest {

    @Test
    public void transformOrganisation_shouldTransformOrganisation() throws Exception {
        OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
        OrganizationUnmarshaller unmarshaller = new OrganizationUnmarshaller(openSamlXmlObjectFactory);
        String organisationName = "BigCorp";

        final OrganisationDto dto = anOrganisationDto().withDisplayName(organisationName).build();

        Organization organisation = unmarshaller.fromDto(dto);

        assertThat(organisation).isNotNull();
        assertThat(organisation.getDisplayNames().size()).isEqualTo(1);
        OrganizationDisplayName organizationDisplayName = organisation.getDisplayNames().get(0);
        assertThat(organizationDisplayName.getXMLLang()).isEqualTo("en-GB");
        assertThat(organizationDisplayName.getValue()).isEqualTo(organisationName);
    }
}
