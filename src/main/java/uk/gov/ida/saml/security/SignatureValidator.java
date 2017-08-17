package uk.gov.ida.saml.security;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidationParametersCriterion;
import uk.gov.ida.saml.security.validators.signablexmlobject.SignatureAlgorithmValidator;

import javax.xml.namespace.QName;
import java.util.Arrays;
import java.util.List;

public abstract class SignatureValidator {
    private final SAMLSignatureProfileValidator samlSignatureProfileValidator = new SAMLSignatureProfileValidator();
    private final SignatureAlgorithmValidator signatureAlgorithmValidator = new SignatureAlgorithmValidator();

    public final boolean validate(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException, SignatureException {
        Signature signature = signableSAMLObject.getSignature();

        if (signature == null) {
            throw new SignatureException("Signature in signableSAMLObject is null");
        }

        /*
            TODO: This check is repeated in the SignatureValidationParametersCriterion but the behaviour is different
            as signatureAlgorithmValidator.validate throws when validation fails but the criterion return false. Both
            are included so as keep previous behaviour of signature algorithm validation. JIRA: TT-1003
         */
        signatureAlgorithmValidator.validate(signableSAMLObject);
        samlSignatureProfileValidator.validate(signature);

        List<Criterion> additionalCriteria = getAdditionalCriteria(entityId, role);
        CriteriaSet criteria = new CriteriaSet();

        SignatureValidationParameters signatureValidationParameters = new SignatureValidationParameters();
        signatureValidationParameters.setWhitelistedAlgorithms(Arrays.asList(
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512,
                SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA1,
                SignatureConstants.ALGO_ID_DIGEST_SHA1,
                SignatureConstants.ALGO_ID_DIGEST_SHA256,
                SignatureConstants.ALGO_ID_DIGEST_SHA512
        ));
        criteria.add(new SignatureValidationParametersCriterion(signatureValidationParameters));

        criteria.addAll(additionalCriteria);

        return getTrustEngine(entityId).validate(signableSAMLObject.getSignature(), criteria);
    }

    protected abstract TrustEngine<Signature> getTrustEngine(String entityId);

    protected abstract List<Criterion> getAdditionalCriteria(String entityId, QName role);
}
