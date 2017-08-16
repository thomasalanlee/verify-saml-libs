package uk.gov.ida.saml.security;

import com.google.common.collect.ImmutableList;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import uk.gov.ida.saml.core.validation.SamlValidationSpecificationFailure;
import uk.gov.ida.saml.security.exception.SamlFailedToDecryptException;
import uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory;
import uk.gov.ida.saml.security.validators.ValidatedEncryptedAssertionContainer;
import uk.gov.ida.saml.security.validators.encryptedelementtype.EncryptionAlgorithmValidator;

import java.util.List;

public class AssertionDecrypter {
    protected final IdaKeyStoreCredentialRetriever keyStoreCredentialRetriever;
    protected final DecrypterFactory decrypterFactory;
    protected final EncryptionAlgorithmValidator encryptionAlgorithmValidator;

    public AssertionDecrypter(IdaKeyStoreCredentialRetriever keyStoreCredentialRetriever, EncryptionAlgorithmValidator encryptionAlgorithmValidator, DecrypterFactory decrypterFactory) {
        this.keyStoreCredentialRetriever = keyStoreCredentialRetriever;
        this.encryptionAlgorithmValidator = encryptionAlgorithmValidator;
        this.decrypterFactory = decrypterFactory;
    }

    public List<Assertion> decryptAssertions(ValidatedEncryptedAssertionContainer container) {
        final List<EncryptedAssertion> encryptedAssertions = container.getEncryptedAssertions();
        final ImmutableList.Builder<Assertion> assertions = ImmutableList.builder();

        if (!encryptedAssertions.isEmpty()) {
            List<Credential> credential = keyStoreCredentialRetriever.getDecryptingCredentials();
            Decrypter decrypter = decrypterFactory.createDecrypter(credential);
            decrypter.setRootInNewDocument(true);

            for (EncryptedAssertion encryptedAssertion : encryptedAssertions) {
                try {
                    encryptionAlgorithmValidator.validate(encryptedAssertion);
                    assertions.add(decrypter.decrypt(encryptedAssertion));
                } catch (DecryptionException e) {
                    String message = "Problem decrypting assertion " + encryptedAssertion + ".";
                    SamlValidationSpecificationFailure failure = SamlTransformationErrorFactory.unableToDecrypt(message);
                    throw new SamlFailedToDecryptException(failure.getErrorMessage(), e, failure.getLogLevel());
                }
            }
        }

        return assertions.build();
    }
}
