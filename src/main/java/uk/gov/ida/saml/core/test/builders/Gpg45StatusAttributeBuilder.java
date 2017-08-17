package uk.gov.ida.saml.core.test.builders;

import com.google.common.base.Optional;
import org.opensaml.saml.saml2.core.Attribute;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.extensions.Gpg45Status;

import static com.google.common.base.Optional.fromNullable;

public class Gpg45StatusAttributeBuilder {

    private OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
    private Optional<String> value = fromNullable("IT01");

    public static Gpg45StatusAttributeBuilder aGpg45StatusAttribute() {
        return new Gpg45StatusAttributeBuilder();
    }

    public Attribute build() {
        Attribute attribute = openSamlXmlObjectFactory.createAttribute();
        attribute.setName(IdaConstants.Attributes_1_1.GPG45Status.NAME);
        if (value.isPresent()){
            Gpg45Status attributeValue = openSamlXmlObjectFactory.createGpg45StatusAttributeValue(value.get());
            attribute.getAttributeValues().add(attributeValue);
        }

        return attribute;
    }

    public Gpg45StatusAttributeBuilder withValue(String value){
        this.value = fromNullable(value);
        return this;
    }
}
