package uk.gov.ida.saml.serializers;

import com.google.common.base.Throwables;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.gov.ida.shared.utils.string.StringEncoding;
import uk.gov.ida.shared.utils.xml.XmlUtils;

import javax.xml.parsers.ParserConfigurationException;
import java.util.function.Function;

public class XmlObjectToBase64EncodedStringTransformer<TInput extends XMLObject> implements Function<TInput,String> {

    @Override
    public String apply(XMLObject signableXMLObject) {
        String result;
        Element signedElement = marshallToElement(signableXMLObject);
        result = XmlUtils.writeToString(signedElement);
        return StringEncoding.toBase64Encoded(result);
    }

    private static Element marshallToElement(XMLObject rootObject) {
        Element result;
        try {
            marshallToXml(rootObject);
            result = rootObject.getDOM();
        } catch (ParserConfigurationException | MarshallingException e) {
            throw Throwables.propagate(e);
        }
        return result;
    }

    private static Document marshallToXml(XMLObject samlXml) throws ParserConfigurationException, MarshallingException {
        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();

        Marshaller responseMarshaller = marshallerFactory.getMarshaller(samlXml);

        Document document = XmlUtils.newDocumentBuilder().newDocument();
        responseMarshaller.marshall(samlXml, document);

        return document;
    }

}
