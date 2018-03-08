package uk.gov.ida.saml.security;

import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;

import javax.inject.Inject;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class SigningCredentialFactory {
    private final SigningKeyStore signingKeyStore;

    @Inject
    public SigningCredentialFactory(SigningKeyStore signingKeyStore) {
        this.signingKeyStore = signingKeyStore;
    }

    public List<Credential> getVerifyingCredentials(String entityId) {
        ArrayList<Credential> verifyingCredentials = new ArrayList<>();
        List<PublicKey> verifyingKeysForEntity = signingKeyStore.getVerifyingKeysForEntity(entityId);
        for(PublicKey verifyingKeyForEntity: verifyingKeysForEntity){
            BasicCredential credential = new BasicCredential(verifyingKeyForEntity);
            credential.setUsageType(UsageType.SIGNING);
            verifyingCredentials.add(credential);
        }
        return verifyingCredentials;
    }

}
