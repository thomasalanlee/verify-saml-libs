package uk.gov.ida.saml.security.validators.signature;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;

import uk.gov.ida.common.shared.security.PrivateKeyFactory;
import uk.gov.ida.common.shared.security.PublicKeyFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.core.validation.SamlValidationResponse;
import uk.gov.ida.saml.security.CredentialFactorySignatureValidator;
import uk.gov.ida.saml.security.DateTimeFreezer;
import uk.gov.ida.saml.security.HardCodedKeyStore;
import uk.gov.ida.saml.security.SamlMessageSignatureValidator;
import uk.gov.ida.saml.security.SigningCredentialFactory;
import uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.saml.SamlTransformationErrorManagerTestHelper;

import static uk.gov.ida.saml.security.saml.builders.IssuerBuilder.anIssuer;
import static uk.gov.ida.saml.security.saml.builders.ResponseBuilder.aResponse;

@RunWith(OpenSAMLMockitoRunner.class)
public class SamlResponseSignatureValidatorTest {


    private Credential signingCredential;
    private SamlResponseSignatureValidator validator;

    @Before
    public void setup() {
        PublicKeyFactory publicKeyFactory = new PublicKeyFactory(new X509CertificateFactory());
        PrivateKey privateKey = new PrivateKeyFactory().createPrivateKey(Base64.decodeBase64(TestCertificateStrings.STUB_IDP_PUBLIC_PRIMARY_PRIVATE_KEY));
        PublicKey publicKey = publicKeyFactory.createPublicKey(TestCertificateStrings.STUB_IDP_PUBLIC_PRIMARY_CERT);

        BasicCredential basicSigningCredential = new BasicCredential(publicKey, privateKey);
        basicSigningCredential.setUsageType(UsageType.SIGNING);
        signingCredential = basicSigningCredential;

        HardCodedKeyStore hubKeyStore = new HardCodedKeyStore(TestEntityIds.STUB_IDP_ONE);
        SigningCredentialFactory signingCredentialFactory = new SigningCredentialFactory(hubKeyStore);
        final CredentialFactorySignatureValidator signatureValidator = new CredentialFactorySignatureValidator(signingCredentialFactory);
        SamlMessageSignatureValidator samlMessageSignatureValidator = new SamlMessageSignatureValidator(signatureValidator);
        validator = new SamlResponseSignatureValidator(samlMessageSignatureValidator);
    }

    @After
    public void tearDown() throws Exception {
        DateTimeFreezer.unfreezeTime();
    }

    @Test
    public void decorate_shouldValidateResponse() throws Exception {
        DateTimeFreezer.freezeTime(new DateTime(2012, 2, 12, 0, 0));
        Issuer responseIssuer = anIssuer().withIssuerId(TestEntityIds.STUB_IDP_ONE).build();

        Response processedResponse = aResponse()
                .withSigningCredential(signingCredential)
                .withIssuer(responseIssuer)
                .build();

        validator.validate(processedResponse, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    }

    @Test
    public void decorate_shouldFailOnImproperlySignedResponse() throws Exception {
        DateTimeFreezer.freezeTime(new DateTime(2012, 2, 12, 0, 0));
        final Response processedResponse = aResponse()
                .withSigningCredential(signingCredential)
                .withIssuer(anIssuer().withIssuerId(TestEntityIds.HUB_ENTITY_ID).build())
                .build();

        SamlTransformationErrorManagerTestHelper.validateFail(() -> this.validator.validate(processedResponse, IDPSSODescriptor.DEFAULT_ELEMENT_NAME),
                SamlValidationResponse.anInvalidResponse(SamlTransformationErrorFactory.invalidMessageSignature()).getSamlValidationSpecificationFailure());
    }
}
