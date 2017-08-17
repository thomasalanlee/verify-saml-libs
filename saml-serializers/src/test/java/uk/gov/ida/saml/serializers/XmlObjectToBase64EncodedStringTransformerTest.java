package uk.gov.ida.saml.serializers;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import uk.gov.ida.saml.core.test.OpenSAMLRunner;
import uk.gov.ida.shared.utils.string.StringEncoding;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(OpenSAMLRunner.class)
public class XmlObjectToBase64EncodedStringTransformerTest {

    private static final String REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:AuthnRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Version=\"2.0\"/>";

    private XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer;

    @Before
    public void setup() {
        xmlObjectToBase64EncodedStringTransformer = new XmlObjectToBase64EncodedStringTransformer();
    }


    @Test
    public void shouldTransformAuthnRequestToBase64EncodedString() throws Exception {
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();

        String saml = xmlObjectToBase64EncodedStringTransformer.apply(authnRequest);
        assertThat(saml).isEqualTo((StringEncoding.toBase64Encoded(REQUEST)));
    }
}
