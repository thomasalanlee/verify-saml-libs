package uk.gov.ida.saml.security;

import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.saml.security.validators.signablexmlobject.SignatureAlgorithmValidator;

import javax.xml.namespace.QName;

public abstract class SignatureValidator {
    private final SAMLSignatureProfileValidator samlSignatureProfileValidator = new SAMLSignatureProfileValidator();
    private final SignatureAlgorithmValidator signatureAlgorithmValidator = new SignatureAlgorithmValidator();

    public final boolean validate(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException, SignatureException {
        Signature signature = signableSAMLObject.getSignature();

        if (signature == null) {
            throw new SignatureException("Signature in signableSAMLObject is null");
        }

        signatureAlgorithmValidator.validate(signableSAMLObject);
        samlSignatureProfileValidator.validate(signature);

        return this.additionalValidations(signableSAMLObject, entityId, role);
    }

    protected abstract boolean additionalValidations(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException, SecurityException;

}
