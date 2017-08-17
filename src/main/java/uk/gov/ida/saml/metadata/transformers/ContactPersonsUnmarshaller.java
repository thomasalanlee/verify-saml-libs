package uk.gov.ida.saml.metadata.transformers;

import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.domain.ContactPersonDto;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class ContactPersonsUnmarshaller {

    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory;

    public ContactPersonsUnmarshaller(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) {
        this.openSamlXmlObjectFactory = openSamlXmlObjectFactory;
    }

    public List<ContactPerson> fromDto(Collection<ContactPersonDto> contactPersons) {
        List<ContactPerson> transformedContactPersons = new ArrayList<>();

        for (ContactPersonDto contactPersonDto : contactPersons) {
            ContactPerson transformedContactPerson = openSamlXmlObjectFactory.createContactPerson();
            transformedContactPerson.setGivenName(openSamlXmlObjectFactory.createGivenName(contactPersonDto.getGivenName()));
            transformedContactPerson.setSurName(openSamlXmlObjectFactory.createSurName(contactPersonDto.getSurName()));
            transformedContactPerson.setCompany(openSamlXmlObjectFactory.createCompany(contactPersonDto.getCompanyName()));
            transformedContactPerson.setType(ContactPersonTypeEnumeration.SUPPORT);

            for (URI address : contactPersonDto.getEmailAddresses()) {
                transformedContactPerson.getEmailAddresses().add(openSamlXmlObjectFactory.createEmailAddress(address.toString()));
            }

            for (String number : contactPersonDto.getTelephoneNumbers()) {
                transformedContactPerson.getTelephoneNumbers().add(openSamlXmlObjectFactory.createTelephoneNumber(number));
            }
            transformedContactPersons.add(transformedContactPerson);

        }
        return transformedContactPersons;

    }
}
