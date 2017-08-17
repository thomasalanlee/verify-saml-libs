package uk.gov.ida.saml.metadata.transformers;

import org.opensaml.saml.saml2.metadata.Organization;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.domain.OrganisationDto;

public class OrganizationUnmarshaller {

    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory;

    public OrganizationUnmarshaller(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) {
        this.openSamlXmlObjectFactory = openSamlXmlObjectFactory;
    }

    public Organization fromDto(OrganisationDto organisationDto) {

        Organization transformedOrganisation = openSamlXmlObjectFactory.createOrganization();
        transformedOrganisation.getDisplayNames().add(openSamlXmlObjectFactory.createOrganizationDisplayName(organisationDto.getDisplayName()));
        transformedOrganisation.getOrganizationNames().add(openSamlXmlObjectFactory.createOrganizationName(organisationDto.getName()));
        transformedOrganisation.getURLs().add(openSamlXmlObjectFactory.createOrganizationUrl(organisationDto.getUrl()));
        return transformedOrganisation;
    }
}
