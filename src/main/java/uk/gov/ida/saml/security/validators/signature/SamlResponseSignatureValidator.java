package uk.gov.ida.saml.security.validators.signature;

import org.opensaml.saml.saml2.core.Response;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.core.validation.SamlValidationResponse;
import uk.gov.ida.saml.core.validation.SamlValidationSpecificationFailure;
import uk.gov.ida.saml.security.SamlMessageSignatureValidator;
import uk.gov.ida.saml.security.validators.ValidatedResponse;

import javax.xml.namespace.QName;

public class SamlResponseSignatureValidator {

    private final SamlMessageSignatureValidator samlMessageSignatureValidator;

    public SamlResponseSignatureValidator(SamlMessageSignatureValidator samlMessageSignatureValidator) {
        this.samlMessageSignatureValidator = samlMessageSignatureValidator;
    }

    public ValidatedResponse validate(Response response, QName role) throws SamlTransformationErrorException {
        final SamlValidationResponse samlValidationResponse = samlMessageSignatureValidator.validate(response, role);

        if(!samlValidationResponse.isOK()) {
            SamlValidationSpecificationFailure failure = samlValidationResponse.getSamlValidationSpecificationFailure();
            if (samlValidationResponse.getCause() != null)
                throw new SamlTransformationErrorException(failure.getErrorMessage(), samlValidationResponse.getCause(), failure.getLogLevel());
            throw new SamlTransformationErrorException(failure.getErrorMessage(), failure.getLogLevel());
        }
        return new ValidatedResponse(response);
    }

}
