package uk.gov.ida.saml.metadata.transformers;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;

import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.common.shared.security.IdGenerator;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.domain.AssertionConsumerServiceEndpointDto;
import uk.gov.ida.saml.metadata.domain.HubServiceProviderMetadataDto;

public class HubServiceProviderMetadataDtoToEntityDescriptorTransformer implements Function<HubServiceProviderMetadataDto,EntityDescriptor> {

    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory;
    private final OrganizationUnmarshaller organizationUnmarshaller;
    private final ContactPersonsUnmarshaller contactPersonsUnmarshaller;
    private final AssertionConsumerServicesUnmarshaller assertionConsumerServicesUnmarshaller;
    private final KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller;
    private final IdGenerator idGenerator;

    public HubServiceProviderMetadataDtoToEntityDescriptorTransformer(
            OpenSamlXmlObjectFactory openSamlXmlObjectFactory,
            OrganizationUnmarshaller organizationUnmarshaller,
            ContactPersonsUnmarshaller contactPersonsUnmarshaller,
            KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller,
            AssertionConsumerServicesUnmarshaller assertionConsumerServicesUnmarshaller,
            IdGenerator idGenerator) {

        this.openSamlXmlObjectFactory = openSamlXmlObjectFactory;
        this.organizationUnmarshaller = organizationUnmarshaller;
        this.contactPersonsUnmarshaller = contactPersonsUnmarshaller;
        this.keyDescriptorsUnmarshaller = keyDescriptorsUnmarshaller;
        this.assertionConsumerServicesUnmarshaller = assertionConsumerServicesUnmarshaller;
        this.idGenerator = idGenerator;
    }

    @Override
    public EntityDescriptor apply(HubServiceProviderMetadataDto dto) {
        EntityDescriptor entityDescriptor = openSamlXmlObjectFactory.createEntityDescriptor();

        entityDescriptor.setID(idGenerator.getId());
        entityDescriptor.setEntityID(dto.getEntityId());
        entityDescriptor.setValidUntil(dto.getValidUntil());

        SPSSODescriptor roleDescriptor = openSamlXmlObjectFactory.createSPSSODescriptor();
        roleDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        List<Certificate> certificates = new ArrayList<>();
        certificates.addAll(dto.getCertificates());
        roleDescriptor.getKeyDescriptors().addAll(keyDescriptorsUnmarshaller.fromCertificates(certificates));

        entityDescriptor.getRoleDescriptors().add(roleDescriptor);

        final Organization transformedOrganisation = organizationUnmarshaller.fromDto(dto.getOrganisation());
        entityDescriptor.setOrganization(transformedOrganisation);

        final List<ContactPerson> transformedContactPersons = contactPersonsUnmarshaller.fromDto(dto.getContactPersons());
        entityDescriptor.getContactPersons().addAll(transformedContactPersons);

        List<AssertionConsumerServiceEndpointDto> assertionConsumerServiceBindings = dto.getAssertionConsumerServiceBindings();
        List<AssertionConsumerService> assertionConsumerServices = assertionConsumerServicesUnmarshaller.fromDto(assertionConsumerServiceBindings);

        roleDescriptor.getAssertionConsumerServices().addAll(assertionConsumerServices);

        return entityDescriptor;
    }

}
