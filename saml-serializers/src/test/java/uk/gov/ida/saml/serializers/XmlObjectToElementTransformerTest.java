package uk.gov.ida.saml.serializers;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.w3c.dom.Element;

import static org.junit.Assert.*;

public class XmlObjectToElementTransformerTest {

    private static final String REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:AuthnRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Version=\"2.0\"/>";


    @Before
    public void setup() throws InitializationException {
        InitializationService.initialize();
    }

    @Test
    public void shouldTransformAuthnRequestToBase64EncodedString() throws Exception {
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
        Element element = new XmlObjectToElementTransformer<>().apply(authnRequest);

    }

}