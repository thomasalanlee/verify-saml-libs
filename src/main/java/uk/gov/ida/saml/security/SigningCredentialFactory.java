package uk.gov.ida.saml.security;

import com.google.inject.Inject;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class SigningCredentialFactory extends CredentialFactory{
    private final SigningKeyStore signingKeyStore;

    @Inject
    public SigningCredentialFactory(SigningKeyStore signingKeyStore) {
        this.signingKeyStore = signingKeyStore;
    }

    public List<Credential> getVerifyingCredentials(String entityId) {
        ArrayList<Credential> verifyingCredentials = new ArrayList<>();
        List<PublicKey> verifyingKeysForEntity = signingKeyStore.getVerifyingKeysForEntity(entityId);
        for(PublicKey verifyingKeyForEntity: verifyingKeysForEntity){
            verifyingCredentials.add(getCredential(verifyingKeyForEntity, UsageType.SIGNING));
        }
        return verifyingCredentials;
    }
}
