package uk.gov.ida.saml.security;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.saml.security.validators.signablexmlobject.SignatureAlgorithmValidator;

import javax.xml.namespace.QName;
import java.util.List;

public abstract class SignatureValidator {
    private final SAMLSignatureProfileValidator samlSignatureProfileValidator = new SAMLSignatureProfileValidator();
    private final SignatureAlgorithmValidator signatureAlgorithmValidator = new SignatureAlgorithmValidator();

    public final boolean validate(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException, SignatureException {
        Signature signature = signableSAMLObject.getSignature();

        if (signature == null) {
            throw new SignatureException("Signature in signableSAMLObject is null");
        }

        // TODO replace these with default criteria
        signatureAlgorithmValidator.validate(signableSAMLObject);

        samlSignatureProfileValidator.validate(signature);

        List<Criterion> additionalCriteria = getAdditionalCriteria(entityId, role);
        CriteriaSet criteria = new CriteriaSet();
        criteria.addAll(additionalCriteria);

        return getTrustEngine(entityId).validate(signableSAMLObject.getSignature(), criteria);
    }

    protected abstract TrustEngine<Signature> getTrustEngine(String entityId);

    protected abstract List<Criterion> getAdditionalCriteria(String entityId, QName role);
}
