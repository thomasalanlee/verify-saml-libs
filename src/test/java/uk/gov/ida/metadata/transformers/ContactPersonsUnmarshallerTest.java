package uk.gov.ida.metadata.transformers;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.test.OpenSAMLRunner;
import uk.gov.ida.saml.metadata.domain.ContactPersonDto;
import uk.gov.ida.saml.metadata.transformers.ContactPersonsUnmarshaller;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.saml.core.test.builders.ContactPersonDtoBuilder.aContactPersonDto;

@RunWith(OpenSAMLRunner.class)
public class ContactPersonsUnmarshallerTest {

  private ContactPersonsUnmarshaller unmarshaller;

  @Before
  public void setUp() throws Exception {
    OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
    unmarshaller = new ContactPersonsUnmarshaller(openSamlXmlObjectFactory);
  }

  @Test
  public void transformContactPerson_shouldTransformNames() throws Exception {
    ContactPersonDto contactPerson = aContactPersonDto().withGivenName("given").withSurName("surname").build();
    List<ContactPersonDto> contactPersons = newArrayList(contactPerson);

    final List<ContactPerson> transformedContactPersons = unmarshaller.fromDto(contactPersons);

    assertThat(transformedContactPersons.get(0).getGivenName().getName()).isEqualTo("given");
    assertThat(transformedContactPersons.get(0).getSurName().getName()).isEqualTo("surname");
  }

  @Test
  public void transformContactPerson_shouldTransformCompany() throws Exception {
    String companyName = UUID.randomUUID().toString();
    ContactPersonDto contactPerson = aContactPersonDto().withCompanyName(companyName).build();
    List<ContactPersonDto> contactPersons = newArrayList(contactPerson);



    final List<ContactPerson> transformedContactPersons = unmarshaller.fromDto(contactPersons);

    assertThat(transformedContactPersons.get(0).getCompany().getName()).isEqualTo(companyName);
  }

  @Test
  public void transformContactPerson_shouldTransformEmailAddresses() throws Exception {
    final String emailAddressOne = "mail:foo@example.com";
    final String emailAddressTwo = "mail:bar@example.com";
    ContactPersonDto contactPerson = aContactPersonDto()
        .addEmailAddress(URI.create(emailAddressOne))
        .addEmailAddress(URI.create(emailAddressTwo))
        .build();
    List<ContactPersonDto> contactPersons = newArrayList(contactPerson);

    final List<ContactPerson> transformedContactPersons = unmarshaller.fromDto(contactPersons);

    assertThat(transformedContactPersons.get(0).getEmailAddresses().size()).isEqualTo(2);
    assertThat(transformedContactPersons.get(0).getEmailAddresses().get(0).getAddress()).isEqualTo(emailAddressOne);
    assertThat(transformedContactPersons.get(0).getEmailAddresses().get(1).getAddress()).isEqualTo(emailAddressTwo);
  }

  @Test
  public void transformContactPerson_shouldTransformTelephoneNumbers() throws Exception {
    final String telephoneNumberOne = "0115 496 0000";
    final String telephoneNumberTwo = "0118 496 0000";
    ContactPersonDto contactPerson = aContactPersonDto()
        .addTelephoneNumber(telephoneNumberOne)
        .addTelephoneNumber(telephoneNumberTwo)
        .build();

    List<ContactPersonDto> contactPersons = newArrayList(contactPerson);

    final List<ContactPerson> transformedContactPersons = unmarshaller.fromDto(contactPersons);

    assertThat(transformedContactPersons.get(0).getTelephoneNumbers().size()).isEqualTo(2);
    assertThat(transformedContactPersons.get(0).getTelephoneNumbers().get(0).getNumber()).isEqualTo(telephoneNumberOne);
    assertThat(transformedContactPersons.get(0).getTelephoneNumbers().get(1).getNumber()).isEqualTo(telephoneNumberTwo);
  }

  @Test
  public void transformationOnAListWithMultipleItemsShouldReturnListWithCorrectNumberOfElements(){
    ContactPersonDto contactPerson = aContactPersonDto().build();
    List<ContactPersonDto> contactPersons = newArrayList(contactPerson, contactPerson);

    final List <ContactPerson> transformedContactPersons = unmarshaller.fromDto(contactPersons);

    assertThat(transformedContactPersons.size()).isEqualTo(2);
  }
}
