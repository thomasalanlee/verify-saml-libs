package uk.gov.ida.saml.security;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;

import javax.xml.namespace.QName;

public class MetadataBackedEncryptionCredentialResolver implements EncryptionCredentialResolver {

    private CredentialResolver credentialResolver;
    private QName role;

    public MetadataBackedEncryptionCredentialResolver(CredentialResolver credentialResolver, QName role) {
        this.credentialResolver = credentialResolver;
        this.role = role;
    }

    @Override
    public Credential getEncryptingCredential(String receiverId) {
        CriteriaSet criteria = new CriteriaSet();
        criteria.add(new EntityIdCriterion(receiverId));
        criteria.add(new EntityRoleCriterion(role));
        criteria.add(new UsageCriterion(UsageType.ENCRYPTION));
        try {
            return credentialResolver.resolveSingle(criteria);
        } catch (ResolverException e) {
            throw new RuntimeException(e);
        }
    }
}
