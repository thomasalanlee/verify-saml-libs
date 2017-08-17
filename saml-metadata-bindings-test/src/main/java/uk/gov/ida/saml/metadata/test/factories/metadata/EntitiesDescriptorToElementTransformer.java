package uk.gov.ida.saml.metadata.test.factories.metadata;

import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.base.Throwables;

import static uk.gov.ida.shared.utils.xml.XmlUtils.newDocumentBuilder;

class EntitiesDescriptorToElementTransformer {

    public Element transform(EntitiesDescriptor entitiesDescriptor) {
        Element result;
        try {
            marshallToXml(entitiesDescriptor);
            result = entitiesDescriptor.getDOM();
        } catch (ParserConfigurationException | MarshallingException e) {
            throw Throwables.propagate(e);
        }
        return result;
    }

    private Document marshallToXml(EntitiesDescriptor samlXml) throws ParserConfigurationException, MarshallingException {
        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();

        Marshaller responseMarshaller = marshallerFactory.getMarshaller(samlXml);

        Document document = newDocumentBuilder().newDocument();
        responseMarshaller.marshall(samlXml, document);

        return document;
    }

}
