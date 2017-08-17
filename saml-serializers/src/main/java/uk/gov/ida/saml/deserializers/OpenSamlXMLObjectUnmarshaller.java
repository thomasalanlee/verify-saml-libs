package uk.gov.ida.saml.deserializers;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.xml.sax.SAXException;
import uk.gov.ida.saml.deserializers.parser.SamlObjectParser;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.core.validation.SamlValidationSpecificationFailure;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

import static uk.gov.ida.saml.errors.SamlTransformationErrorFactory.unableToDeserializeStringToOpenSaml;

public class OpenSamlXMLObjectUnmarshaller<TOutput extends XMLObject> {

    private final SamlObjectParser samlObjectParser;

    public OpenSamlXMLObjectUnmarshaller(SamlObjectParser samlObjectParser) {
        this.samlObjectParser = samlObjectParser;
    }

    public TOutput fromString(String input) {
        try {
            return samlObjectParser.getSamlObject(input);
        } catch (ParserConfigurationException | SAXException | IOException | UnmarshallingException e) {
            SamlValidationSpecificationFailure failure = unableToDeserializeStringToOpenSaml(input);
            throw new SamlTransformationErrorException(failure.getErrorMessage(), e, failure.getLogLevel());
        }
    }
}
