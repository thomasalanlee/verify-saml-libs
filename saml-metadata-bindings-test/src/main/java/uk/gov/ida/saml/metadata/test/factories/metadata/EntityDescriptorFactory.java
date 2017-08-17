package uk.gov.ida.saml.metadata.test.factories.metadata;

import static java.util.Arrays.asList;

import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;

import com.google.common.base.Throwables;

import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.core.test.builders.metadata.AttributeAuthorityDescriptorBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.EntityDescriptorBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.IdpSsoDescriptorBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.KeyDescriptorBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.KeyInfoBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.SPSSODescriptorBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.X509CertificateBuilder;
import uk.gov.ida.saml.core.test.builders.metadata.X509DataBuilder;

public class EntityDescriptorFactory {

    public EntityDescriptor hubEntityDescriptor() {
        X509Certificate x509CertificateOne = X509CertificateBuilder.aX509Certificate().withCert(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT).build();
        X509Data x509DataOne = X509DataBuilder.aX509Data().withX509Certificate(x509CertificateOne).build();
        KeyInfo signingOne = KeyInfoBuilder.aKeyInfo().withKeyName("signing_one").withX509Data(x509DataOne).build();
        KeyDescriptor keyDescriptorOne = KeyDescriptorBuilder.aKeyDescriptor().withKeyInfo(signingOne).build();
        X509Certificate x509CertificateTwo = X509CertificateBuilder.aX509Certificate().withCert(TestCertificateStrings.HUB_TEST_SECONDARY_PUBLIC_SIGNING_CERT).build();
        X509Data x509DataTwo = X509DataBuilder.aX509Data().withX509Certificate(x509CertificateTwo).build();
        KeyInfo signingTwo = KeyInfoBuilder.aKeyInfo().withKeyName("signing_two").withX509Data(x509DataTwo).build();
        KeyDescriptor keyDescriptorTwo = KeyDescriptorBuilder.aKeyDescriptor().withKeyInfo(signingTwo).build();
        X509Certificate encryptionCertificate = X509CertificateBuilder.aX509Certificate().withCert(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT).build();
        X509Data encryptionX509Data= X509DataBuilder.aX509Data().withX509Certificate(encryptionCertificate).build();
        KeyInfo encryptionKeyInfo= KeyInfoBuilder.aKeyInfo().withKeyName("encryption").withX509Data(encryptionX509Data).build();
        KeyDescriptor encryptionKeyDescriptor = KeyDescriptorBuilder.aKeyDescriptor().withUse("ENCRYPTION").withKeyInfo(encryptionKeyInfo).build();
        SPSSODescriptor spssoDescriptor = SPSSODescriptorBuilder.anSpServiceDescriptor()
                .addKeyDescriptor(keyDescriptorOne)
                .addKeyDescriptor(keyDescriptorTwo)
                .addKeyDescriptor(encryptionKeyDescriptor)
                .withoutDefaultSigningKey()
                .withoutDefaultEncryptionKey().build();
        try {
            return EntityDescriptorBuilder.anEntityDescriptor()
                    .withEntityId(TestEntityIds.HUB_ENTITY_ID)
                    .addSpServiceDescriptor(spssoDescriptor)
                    .withIdpSsoDescriptor(null)
                    .withValidUntil(DateTime.now().plusWeeks(2))
                    .withSignature(null)
                    .withoutSigning()
                    .build();
        } catch (MarshallingException | SignatureException e) {
            throw Throwables.propagate(e);
        }
    }

    public EntityDescriptor idpEntityDescriptor(String idpEntityId) {
        KeyDescriptor keyDescriptor = buildKeyDescriptor(idpEntityId);
        IDPSSODescriptor idpssoDescriptor = IdpSsoDescriptorBuilder.anIdpSsoDescriptor().addKeyDescriptor(keyDescriptor).withoutDefaultSigningKey().build();
        try {
            return EntityDescriptorBuilder.anEntityDescriptor()
                    .withEntityId(idpEntityId)
                    .withIdpSsoDescriptor(idpssoDescriptor)
                    .withValidUntil(DateTime.now().plusWeeks(2))
                    .withSignature(null)
                    .withoutSigning()
                    .setAddDefaultSpServiceDescriptor(false)
                    .build();
        } catch (MarshallingException | SignatureException e) {
            throw Throwables.propagate(e);
        }
    }

    public EntityDescriptor attributeAuthorityEntityDescriptor(String attributeAuthorityEntityId) {
        KeyDescriptor keyDescriptor = buildKeyDescriptor(attributeAuthorityEntityId);
        AttributeAuthorityDescriptor attributeAuthorityDescriptor = AttributeAuthorityDescriptorBuilder.anAttributeAuthorityDescriptor().addKeyDescriptor(keyDescriptor).build();
        try {
            return EntityDescriptorBuilder.anEntityDescriptor()
                    .withEntityId(attributeAuthorityEntityId)
                    .withIdpSsoDescriptor(null)
                    .withValidUntil(DateTime.now().plusWeeks(2))
                    .withSignature(null)
                    .withoutSigning()
                    .withAttributeAuthorityDescriptor(attributeAuthorityDescriptor)
                    .setAddDefaultSpServiceDescriptor(false)
                    .build();
        } catch (MarshallingException | SignatureException e) {
            throw Throwables.propagate(e);
        }
    }

    public List<EntityDescriptor> defaultEntityDescriptors() {
        return asList(
            hubEntityDescriptor(),
            idpEntityDescriptor(TestEntityIds.STUB_IDP_ONE),
            idpEntityDescriptor(TestEntityIds.STUB_IDP_TWO),
            idpEntityDescriptor(TestEntityIds.STUB_IDP_THREE),
            idpEntityDescriptor(TestEntityIds.STUB_IDP_FOUR)
        );
    }

    private KeyDescriptor buildKeyDescriptor(String entityId) {
        String certificate = TestCertificateStrings.PUBLIC_SIGNING_CERTS.get(entityId);
        X509Certificate x509Certificate = X509CertificateBuilder.aX509Certificate().withCert(certificate).build();
        X509Data build = X509DataBuilder.aX509Data().withX509Certificate(x509Certificate).build();
        KeyInfo signing_one = KeyInfoBuilder.aKeyInfo().withKeyName("signing_one").withX509Data(build).build();
        return KeyDescriptorBuilder.aKeyDescriptor().withKeyInfo(signing_one).build();
    }
}
