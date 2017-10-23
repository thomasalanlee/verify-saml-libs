package uk.gov.ida.saml.metadata;

import com.google.common.base.Throwables;
import uk.gov.ida.saml.metadata.exception.EmptyTrustStoreException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.function.Supplier;

public class KeyStoreLoader {
    public KeyStore load(String uri, String password) {
        try {
            return load(new FileInputStream(uri), password);
        } catch (FileNotFoundException e) {
            throw Throwables.propagate(e);
        }
    }

    public KeyStore load(InputStream keystoreInputStream, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] charPassword = password.toCharArray();
            // Use a try with resource block to close the input stream once we've read it
            try (InputStream autoCloseableInputStream = keystoreInputStream) {
                keyStore.load(autoCloseableInputStream, charPassword);
            }
            validate(keyStore);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw Throwables.propagate(e);
        }
    }

    public void validate(KeyStore keyStore) {
        int keyStoreSize = 0;
        try {
            keyStoreSize = keyStore.size();
        } catch (KeyStoreException e) {
            Throwables.propagate(e);
        }
        if (keyStoreSize == 0) {
            throw new EmptyTrustStoreException();
        }
    }
}
