package uk.gov.ida.saml.security;

import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;

public class EncrypterFactory {

    public Encrypter createEncrypter(Credential credential) {
        return createAES128Encrypter(credential);
    }

    public Encrypter createAES128Encrypter(Credential credential) {
        return createEncrypter(credential, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
    }

    public Encrypter createAES256Encrypter(Credential credential) {
        return createEncrypter(credential, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
    }

    private Encrypter createEncrypter(Credential credential, String dataEncryptionAlgorithm) {
        DataEncryptionParameters encParams = new DataEncryptionParameters();
        encParams.setAlgorithm(dataEncryptionAlgorithm);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(credential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        Encrypter encrypter = new Encrypter(encParams, kekParams);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

        return encrypter;
    }
}
