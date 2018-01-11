package uk.gov.ida.saml.core.test.builders;

import com.google.common.base.Optional;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.AttributeValue;
import uk.gov.ida.saml.core.test.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.extensions.Date;

public class DateAttributeValueBuilder {

    private OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();

    private Optional<DateTime> from = Optional.absent();
    private Optional<DateTime> to = Optional.absent();
    private String value = "1991-04-12";
    private Optional<Boolean> verified = Optional.absent();

    public static DateAttributeValueBuilder aDateValue() {
        return new DateAttributeValueBuilder();
    }

    public AttributeValue build() {
        Date dateAttributeValue = openSamlXmlObjectFactory.createDateAttributeValue(value);

        if (from.isPresent()) {
            dateAttributeValue.setFrom(from.get());
        }
        if (to.isPresent()) {
            dateAttributeValue.setTo(to.get());
        }
        if (verified.isPresent()) {
            dateAttributeValue.setVerified(verified.get());
        }
        return dateAttributeValue;
    }

    public DateAttributeValueBuilder withFrom(DateTime from) {
        this.from = Optional.fromNullable(from);
        return this;
    }

    public DateAttributeValueBuilder withTo(DateTime to) {
        this.to = Optional.fromNullable(to);
        return this;
    }

    public DateAttributeValueBuilder withValue(String name) {
        this.value = name;
        return this;
    }

    public DateAttributeValueBuilder withVerified(Boolean verified) {
        this.verified = Optional.fromNullable(verified);
        return this;
    }
}
