package uk.gov.ida.saml.security.validators.signablexmlobject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.saml.SamlTransformationErrorManagerTestHelper;
import uk.gov.ida.saml.security.saml.deserializers.XmlUtils;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

@RunWith(OpenSAMLMockitoRunner.class)
public class SignatureAlgorithmValidatorTest {

    private SignatureAlgorithmValidator validator = new SignatureAlgorithmValidator();

    @Before
    public void setup() {
        validator = new SignatureAlgorithmValidator();
    }

    @Test
    public void validate_shouldNotThrowSamlExceptionIfSigningEncryptionAlgorithmIsRsaSHA1() throws Exception {
        String signatureMethodAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
        SignableXMLObject signableXmlObject = createSignableXMLObject(signatureMethodAlgorithm);
        validator.validate(signableXmlObject);
    }

    @Test
    public void validate_shouldNotThrowSamlExceptionIfSigningEncryptionAlgorithmIsDsaSHA1() throws Exception {
        String signatureMethodAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA1;
        SignableXMLObject signableXmlObject = createSignableXMLObject(signatureMethodAlgorithm);
        validator.validate(signableXmlObject);
    }

    @Test
    public void validate_shouldNotThrowSamlExceptionIfSigningEncryptionAlgorithmIsRsaSHA256() throws Exception {
        String signatureMethodAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
        SignableXMLObject signableXmlObject = createSignableXMLObject(signatureMethodAlgorithm);
        validator.validate(signableXmlObject);
    }

    @Test
    public void validate_shouldNotThrowSamlExceptionIfSigningEncryptionAlgorithmIsRsaSHA512() throws Exception {
        String signatureMethodAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;
        SignableXMLObject signableXmlObject = createSignableXMLObject(signatureMethodAlgorithm);
        validator.validate(signableXmlObject);
    }

    @Test
    public void validate_shouldThrowSamlExceptionIfSigningEncryptionAlgorithmIsUnsupported() throws Exception {
        String signatureMethodAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1;
        final SignableXMLObject signableXmlObject = createSignableXMLObject(signatureMethodAlgorithm);

        SamlTransformationErrorManagerTestHelper.validateFail(
                () -> validator.validate(signableXmlObject),
                SamlTransformationErrorFactory.unsupportedSignatureEncryptionAlgortithm(signatureMethodAlgorithm)
        );
    }

    private SignableXMLObject createSignableXMLObject(String signatureMethodAlgorithm) throws UnmarshallingException, IOException, SAXException, ParserConfigurationException {
        String authnRequest = "<saml2p:AuthnRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n" +
                "                     ID=\"dda1c063-7294-4993-b64d-b3e2010ee761\"\n" +
                "                     IssueInstant=\"2012-10-10T10:39:43.011Z\"\n" +
                "                     Version=\"2.0\"\n" +
                "                     xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "    <saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n" +
                "                  Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\"\n" +
                "            >http://www.test-rp.gov.uk/SAML2/MD</saml2:Issuer>\n" +
                "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "        <ds:SignedInfo>\n" +
                "            <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />\n" +
                "            <ds:SignatureMethod Algorithm=\"" + signatureMethodAlgorithm + "\" />\n" +
                "            <ds:Reference URI=\"#dda1c063-7294-4993-b64d-b3e2010ee761\">\n" +
                "                <ds:Transforms>\n" +
                "                    <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n" +
                "                    <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />\n" +
                "                </ds:Transforms>\n" +
                "                <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />\n" +
                "                <ds:DigestValue>vdU04JjVHEFfkmQqMV3LAWs2sQA=</ds:DigestValue>\n" +
                "            </ds:Reference>\n" +
                "        </ds:SignedInfo>\n" +
                "        <ds:SignatureValue>jlBpui7SKxVKZjfrGzqMOKFDoLjvwN+JyfL5Wo4h8jWjlb0iNmSpU84Sj5oIq51C1AT1FXLmPUceYn12N+MvxzkzyR3zQyvjmMdQKcKH3jvDvWJK4Vh+DvW1ac65C8XZxfXvYVBvvCoFYMUYtLWvol5KYjTGKRvQuUSF68ICWi0=</ds:SignatureValue>\n" +
                "    </ds:Signature>\n" +
                "    <saml2:Conditions xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "        <saml2:AudienceRestriction>\n" +
                "            <saml2:Audience/>\n" +
                "        </saml2:AudienceRestriction>\n" +
                "    </saml2:Conditions>\n" +
                "    <saml2p:RequestedAuthnContext Comparison=\"minimum\">\n" +
                "        <AuthnContextClassRef>http://www.cabinetoffice.gov.uk/resource-library/ida/authn-context/level0</AuthnContextClassRef>\n" +
                "    </saml2p:RequestedAuthnContext>\n" +
                "</saml2p:AuthnRequest>";
        final Element element = XmlUtils.convertToElement(authnRequest);
        return (SignableXMLObject) XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(AuthnRequest.TYPE_NAME).unmarshall(element);
    }
}
