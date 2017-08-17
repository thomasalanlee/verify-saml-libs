package uk.gov.ida.saml.serializers;

import com.google.common.base.Throwables;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.ParserConfigurationException;

import java.util.function.Function;

import static uk.gov.ida.shared.utils.xml.XmlUtils.newDocumentBuilder;

public class XmlObjectToElementTransformer<TInput extends XMLObject> implements Function<TInput,Element> {

    public Element apply(TInput rootObject) {
        Element result;
        try {
            marshallToXml(rootObject);
            result = rootObject.getDOM();
        } catch (ParserConfigurationException | MarshallingException e) {
            throw Throwables.propagate(e);
        }
        return result;
    }

    private Document marshallToXml(TInput samlXml) throws ParserConfigurationException, MarshallingException {
        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();

        Marshaller responseMarshaller = marshallerFactory.getMarshaller(samlXml);

        Document document = newDocumentBuilder().newDocument();
        responseMarshaller.marshall(samlXml, document);

        return document;
    }

}
