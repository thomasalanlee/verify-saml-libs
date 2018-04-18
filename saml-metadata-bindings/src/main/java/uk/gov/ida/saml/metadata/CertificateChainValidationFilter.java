package uk.gov.ida.saml.metadata;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import static org.opensaml.xmlsec.keyinfo.KeyInfoSupport.getCertificates;

public final class CertificateChainValidationFilter implements MetadataFilter {

    private final Logger log = LoggerFactory.getLogger(CertificateChainValidationFilter.class);

    private final Role role;
    private final CertificateChainValidator certificateChainValidator;
    private final KeyStore keyStore;

    public CertificateChainValidationFilter(
        @NotNull final Role role,
        @NotNull final CertificateChainValidator certificateChainValidator,
        @NotNull final KeyStore keyStore) {

        this.role = role;
        this.certificateChainValidator = certificateChainValidator;
        this.keyStore = keyStore;
    }

    public Role getRole() {
        return role;
    }

    public CertificateChainValidator getCertificateChainValidator() {
        return certificateChainValidator;
    }

    private KeyStore getKeyStore() {
        return keyStore;
    }

    @Nullable
    @Override
    public XMLObject filter(@Nullable final XMLObject metadata) {
        if (metadata == null) {
            return null;
        }
        if (metadata instanceof EntityDescriptor) {
            processEntityDescriptor((EntityDescriptor) metadata);
        } else if (metadata instanceof EntitiesDescriptor) {
            processEntityGroup((EntitiesDescriptor) metadata);
        } else {
            log.error("Internal error, metadata object was of an unsupported type: {}", metadata.getClass().getName());
        }

        return metadata;
    }

    private void processEntityGroup(final EntitiesDescriptor entitiesDescriptor) {
        final String name = getGroupName(entitiesDescriptor);
        log.trace("Processing EntitiesDescriptor group: {}", name);

        entitiesDescriptor.getEntityDescriptors().forEach(this::processEntityDescriptor);

        entitiesDescriptor.getEntitiesDescriptors().forEach(entitiesChild -> {
            final String childName = getGroupName(entitiesChild);
            log.trace("Processing EntitiesDescriptor member: {}", childName);
            processEntityGroup(entitiesChild);
        });
    }

    private void processEntityDescriptor(final EntityDescriptor entityDescriptor) {
        final String entityID = entityDescriptor.getEntityID();
        log.trace("Processing EntityDescriptor: {}", entityID);

        final Iterator<RoleDescriptor> roleIter = entityDescriptor.getRoleDescriptors().iterator();
        while (roleIter.hasNext()) {
            final RoleDescriptor roleChild = roleIter.next();
            if (!roleChild.getElementQName().equals(getRole().getRoleDescriptor())) {
                log.trace("RoleDescriptor member '{}' was not right role, skipping certificate chain validation processing...", roleChild.getElementQName());
                continue;
            } else {
                log.trace("Processing RoleDescriptor member: {}", roleChild.getElementQName());
            }

            try {
                performCertificateChainValidation(roleChild);
            } catch (final FilterException e) {
                log.error("RoleDescriptor '{}' subordinate to entity '{}' failed certificate chain validation, " + "removing from metadata provider", roleChild.getElementQName(), entityID);
                roleIter.remove();
            }
        }
    }

    private String getGroupName(final EntitiesDescriptor group) {
        String name = group.getName();
        if (name != null) {
            return name;
        }
        name = group.getID();
        if (name != null) {
            return name;
        }
        return "(unnamed)";
    }

    private void performCertificateChainValidation(final RoleDescriptor roleDescriptor) throws FilterException {
        for (final KeyDescriptor keyDescriptor : roleDescriptor.getKeyDescriptors()) {
            KeyInfo keyInfo = keyDescriptor.getKeyInfo();
            try {
                for (final X509Certificate certificate : getCertificates(keyInfo)) {
                    if (!getCertificateChainValidator().validate(certificate, getKeyStore()).isValid()) {
                        log.error("Certificate chain validation failed for metadata entry {}", certificate.getIssuerDN());
                        throw new FilterException("Certificate chain validation failed for metadata entry {}");
                    }
                }
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }
    }
}
