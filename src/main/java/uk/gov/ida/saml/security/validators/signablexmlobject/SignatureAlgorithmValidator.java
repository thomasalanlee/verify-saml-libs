package uk.gov.ida.saml.security.validators.signablexmlobject;

import com.google.common.collect.ImmutableSet;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.core.validation.SamlValidationSpecificationFailure;
import uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory;

import java.util.Set;

public class SignatureAlgorithmValidator {

    private static final Set<String> SUPPORTED_SIGNATURE_SIGNING_ALGORITHMS = ImmutableSet.of(
            SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512,
            SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1,
            SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
            SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA1
    );

    public SignatureAlgorithmValidator() {
    }

    public void validate(SignableXMLObject signableXMLObject) {
        final String signatureAlgorithm = signableXMLObject.getSignature().getSignatureAlgorithm();
        if (!SUPPORTED_SIGNATURE_SIGNING_ALGORITHMS.contains(signatureAlgorithm)) {
            SamlValidationSpecificationFailure failure = SamlTransformationErrorFactory.unsupportedSignatureEncryptionAlgortithm(signatureAlgorithm);
            throw new SamlTransformationErrorException(failure.getErrorMessage(), failure.getLogLevel());
        }
    }
}
