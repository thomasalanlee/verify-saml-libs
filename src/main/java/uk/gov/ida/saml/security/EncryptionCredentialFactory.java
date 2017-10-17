package uk.gov.ida.saml.security;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;

import javax.inject.Inject;

public class EncryptionCredentialFactory extends CredentialFactory {

    private final EncryptionKeyStore encryptionKeyStore;

    @Inject
    public EncryptionCredentialFactory(EncryptionKeyStore encryptionKeyStore) {
        this.encryptionKeyStore = encryptionKeyStore;
    }

    public Credential getEncryptingCredential(String receiverId) {
        return getCredential(encryptionKeyStore.getEncryptionKeyForEntity(receiverId), UsageType.ENCRYPTION);
    }
}
