package uk.gov.ida.saml.metadata.transformers;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.domain.AssertionConsumerServiceEndpointDto;

import java.util.ArrayList;
import java.util.List;

public class AssertionConsumerServicesUnmarshaller {

    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory;

    public AssertionConsumerServicesUnmarshaller(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) {
        this.openSamlXmlObjectFactory = openSamlXmlObjectFactory;
    }

    public List<AssertionConsumerService> fromDto(List<AssertionConsumerServiceEndpointDto> assertionConsumerServiceEndpointDtos) {

        List<AssertionConsumerService> transformedConsumerServiceList = new ArrayList<>();
        for (AssertionConsumerServiceEndpointDto assertionConsumerServiceEndpointDto : assertionConsumerServiceEndpointDtos) {
            String saml2PostBindingUri = SAMLConstants.SAML2_POST_BINDING_URI;

            String location = assertionConsumerServiceEndpointDto.getLocation().toString();
            int index = assertionConsumerServiceEndpointDto.getIndex();
            boolean isDefault = assertionConsumerServiceEndpointDto.getIsDefault();
            AssertionConsumerService transformedAssertionConsumerService = openSamlXmlObjectFactory.createAssertionConsumerService(saml2PostBindingUri, location, index, isDefault);
            transformedConsumerServiceList.add(transformedAssertionConsumerService);
        }
        return transformedConsumerServiceList;
    }
}
