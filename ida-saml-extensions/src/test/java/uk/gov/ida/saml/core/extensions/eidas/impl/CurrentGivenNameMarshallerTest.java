package uk.gov.ida.saml.core.extensions.eidas.impl;

import net.shibboleth.utilities.java.support.xml.XMLConstants;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.w3c.dom.Element;
import uk.gov.ida.saml.core.extensions.eidas.CurrentGivenName;
import uk.gov.ida.saml.core.test.OpenSAMLRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.saml.core.IdaConstants.EIDAS_NATURUAL_PREFIX;

@RunWith(OpenSAMLRunner.class)
public class CurrentGivenNameMarshallerTest {

    @Test
    public void shouldMarshallCurrentGivenName() throws Exception {
        final String firstName = "Javier";
        final CurrentGivenName currentGivenName = new CurrentGivenNameBuilder().buildObject();
        final Marshaller currentGivenNameMarshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(currentGivenName);
        currentGivenName.setFirstName(firstName);

        final Element marshalledElement = currentGivenNameMarshaller.marshall(currentGivenName);

        assertThat(marshalledElement.getNamespaceURI()).isEqualTo(CurrentGivenName.DEFAULT_ELEMENT_NAME.getNamespaceURI());
        assertThat(marshalledElement.getAttributeNS(XMLConstants.XSI_NS, XMLConstants.XSI_TYPE_ATTRIB_NAME.getLocalPart())).isEqualTo(String.format("%s:%s", EIDAS_NATURUAL_PREFIX, CurrentGivenName.TYPE_LOCAL_NAME));
        assertThat(marshalledElement.getTextContent()).isEqualTo(firstName);
    }
}
