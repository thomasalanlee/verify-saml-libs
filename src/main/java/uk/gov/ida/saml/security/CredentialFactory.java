package uk.gov.ida.saml.security;


import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import java.security.PublicKey;

public abstract class CredentialFactory {
    protected Credential getCredential(PublicKey publicKey, UsageType usageType) {
        BasicCredential credential = new BasicCredential(publicKey);

        credential.setUsageType(usageType);
        return credential;
    }
}
