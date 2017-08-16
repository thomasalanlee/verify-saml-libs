package uk.gov.ida.saml.security;


import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;


public class CredentialFactorySignatureValidator extends SignatureValidator {
    private final SigningCredentialFactory credentialFactory;


    public CredentialFactorySignatureValidator(SigningCredentialFactory credentialFactory) {
        this.credentialFactory = credentialFactory;
    }

    @Override
    protected boolean additionalValidations(SignableSAMLObject signableSAMLObject, String entityId, QName role) throws SecurityException {
        List<Credential> credentials = credentialFactory.getVerifyingCredentials(entityId);

        CredentialResolver credResolver = new StaticCredentialResolver(credentials);
        KeyInfoCredentialResolver kiResolver = DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();
        ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);

        return trustEngine.validate(signableSAMLObject.getSignature(), new CriteriaSet(new Criterion() {}));
    }

}
