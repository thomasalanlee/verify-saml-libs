package uk.gov.ida.saml.security;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import javax.xml.namespace.QName;
import java.util.Optional;

public class MetadataBackedSignatureValidator extends SignatureValidator {

    private final ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine;
    private final Optional<CertificateChainEvaluableCriterion> certificateChainEvaluableCriteria;

    public static MetadataBackedSignatureValidator withoutCertificateChainValidation(ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine) {
        return new MetadataBackedSignatureValidator(explicitKeySignatureTrustEngine);
    }

    public static MetadataBackedSignatureValidator withCertificateChainValidation(ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine, CertificateChainEvaluableCriterion certificateChainEvaluableCriterion) {
        return new MetadataBackedSignatureValidator(explicitKeySignatureTrustEngine, certificateChainEvaluableCriterion);
    }

    private MetadataBackedSignatureValidator(ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine) {
        this.explicitKeySignatureTrustEngine = explicitKeySignatureTrustEngine;
        this.certificateChainEvaluableCriteria = Optional.empty();
    }

    private MetadataBackedSignatureValidator(ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine, CertificateChainEvaluableCriterion certificateChainEvaluableCriterion) {
        this.explicitKeySignatureTrustEngine = explicitKeySignatureTrustEngine;
        this.certificateChainEvaluableCriteria = Optional.of(certificateChainEvaluableCriterion);
    }

    @Override
    protected boolean additionalValidations(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException {
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIdCriterion(entityId));
        criteriaSet.add(new EntityRoleCriterion(role));
        this.certificateChainEvaluableCriteria.map(criteriaSet::add);

        return explicitKeySignatureTrustEngine.validate(signableSAMLObject.getSignature(), criteriaSet);
    }
}
