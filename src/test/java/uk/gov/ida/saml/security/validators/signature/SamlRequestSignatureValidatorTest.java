package uk.gov.ida.saml.security.validators.signature;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import uk.gov.ida.saml.core.validation.SamlValidationResponse;
import uk.gov.ida.saml.security.SamlMessageSignatureValidator;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(OpenSAMLMockitoRunner.class)
public class SamlRequestSignatureValidatorTest {

    @Test
    public void validate_shouldDoNothingIfAuthnRequestSignatureIsValid() throws Exception {
        SamlMessageSignatureValidator samlMessageSignatureValidator = mock(SamlMessageSignatureValidator.class);

        SamlRequestSignatureValidator<AuthnRequest> requestSignatureValidator = new SamlRequestSignatureValidator<>(samlMessageSignatureValidator);

        AuthnRequest authnRequest = (AuthnRequest) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME).buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
        String issuerId = "some issuer";
        Issuer issuer = (Issuer) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        authnRequest.setIssuer(issuer);
        issuer.setValue(issuerId);

        when(samlMessageSignatureValidator.validate(authnRequest, SPSSODescriptor.DEFAULT_ELEMENT_NAME)).thenReturn(SamlValidationResponse.aValidResponse());

        requestSignatureValidator.validate(authnRequest, SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        verify(samlMessageSignatureValidator).validate(authnRequest, SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    }
}
