package uk.gov.ida.saml.metadata.test.factories.metadata;

import java.util.List;

import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.w3c.dom.Element;
import uk.gov.ida.shared.utils.xml.XmlUtils;

public class MetadataFactory {
    private final EntitiesDescriptorFactory entitiesDescriptorFactory = new EntitiesDescriptorFactory();
    private final EntitiesDescriptorToElementTransformer entitiesDescriptorEntitiesDescriptorToElementTransformer = new EntitiesDescriptorToElementTransformer();

    public String defaultMetadata() {
        EntitiesDescriptor entitiesDescriptor = entitiesDescriptorFactory.defaultEntitiesDescriptor();
        return metadata(entitiesDescriptor);
    }

    public String emptyMetadata() {
        EntitiesDescriptor entitiesDescriptor = entitiesDescriptorFactory.emptyEntitiesDescriptor();
        return metadata(entitiesDescriptor);
    }

    public String metadata(EntitiesDescriptor entitiesDescriptor) {
        Element element = entitiesDescriptorEntitiesDescriptorToElementTransformer.transform(entitiesDescriptor);
        return XmlUtils.writeToString(element);
    }

    public String metadata(List<EntityDescriptor> entityDescriptors) {
        EntitiesDescriptor metadata = entitiesDescriptorFactory.entitiesDescriptor(entityDescriptors);
        return metadata(metadata);
    }

    public String expiredMetadata() {
        EntitiesDescriptor metadata = entitiesDescriptorFactory.expiredEntitiesDescriptor();
        return metadata(metadata);
    }

    public String unsignedMetadata() {
        EntitiesDescriptor metadata = entitiesDescriptorFactory.unsignedEntitiesDescriptor();
        return metadata(metadata);
    }

    public String signedMetadata(String publicCertificate, String privateKey) {
        EntitiesDescriptor metadata = entitiesDescriptorFactory.signedEntitiesDescriptor(publicCertificate, privateKey);
        return metadata(metadata);
    }

    public String metadataWithFullCertificateChain(String publicCertificate, List<String> certificateChain ,String privateKey) {
        EntitiesDescriptor metadata = entitiesDescriptorFactory.fullChainSignedEntitiesDescriptor(publicCertificate, certificateChain, privateKey);
        return metadata(metadata);
    }
}
