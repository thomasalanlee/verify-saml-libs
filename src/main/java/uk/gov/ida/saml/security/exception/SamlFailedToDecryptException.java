package uk.gov.ida.saml.security.exception;

import org.apache.log4j.Level;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;

public class SamlFailedToDecryptException extends SamlTransformationErrorException {

    public SamlFailedToDecryptException(String errorMessage, Exception cause, Level logLevel) {
        super(errorMessage, cause, logLevel);
    }

    public SamlFailedToDecryptException(String errorMessage, Level logLevel) {
        super(errorMessage, logLevel);
    }
}
