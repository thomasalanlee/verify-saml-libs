package uk.gov.ida.saml.security;

import com.google.inject.Inject;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;

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
