package uk.gov.ida.metadata.transformers;

import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.metadata.domain.AssertionConsumerServiceEndpointDto;
import uk.gov.ida.saml.metadata.transformers.AssertionConsumerServicesUnmarshaller;

import java.net.URI;
import java.util.List;

import static java.util.Arrays.asList;
import static uk.gov.ida.saml.core.test.builders.metadata.AssertionConsumerServiceEndpointDtoBuilder.anAssertionConsumerServiceEndpointDto;

@RunWith(OpenSAMLMockitoRunner.class)
public class AssertionConsumerServicesUnmarshallerTest {

    private AssertionConsumerServicesUnmarshaller unmarshaller;

    @Before
    public void setUp() throws Exception {
        OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
        unmarshaller = new AssertionConsumerServicesUnmarshaller(openSamlXmlObjectFactory);
    }

    @Test
    public void transform_shouldTransformLocation() throws Exception {
        final URI location = URI.create("/foo");
        AssertionConsumerServiceEndpointDto endpoint = anAssertionConsumerServiceEndpointDto()
                .withLocation(location)
                .build();

        final List<AssertionConsumerService> result = unmarshaller.fromDto(asList(endpoint));

        Assertions.assertThat(result.get(0).getLocation()).isEqualTo(location.toString());
    }

    @Test
    public void transform_shouldTransformTwoServices() throws Exception {
        AssertionConsumerServiceEndpointDto endpointOne = anAssertionConsumerServiceEndpointDto()
                .build();
        AssertionConsumerServiceEndpointDto endpointTwo = anAssertionConsumerServiceEndpointDto()
                .build();

        final List<AssertionConsumerService> result = unmarshaller.fromDto(asList(endpointOne, endpointTwo));

        Assertions.assertThat(result.size()).isEqualTo(2);
    }
}
