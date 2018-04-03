package uk.gov.ida.saml.core.transformers;

import java.util.Optional;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.core.domain.AssertionRestrictions;
import uk.gov.ida.saml.core.domain.IdentityProviderAssertion;
import uk.gov.ida.saml.core.domain.IdentityProviderAuthnStatement;
import uk.gov.ida.saml.core.domain.MatchingDataset;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static uk.gov.ida.saml.core.test.builders.AddressAttributeBuilder_1_1.*;
import static uk.gov.ida.saml.core.test.builders.AddressAttributeValueBuilder_1_1.*;
import static uk.gov.ida.saml.core.test.builders.AssertionBuilder.*;
import static uk.gov.ida.saml.core.test.builders.DateAttributeBuilder_1_1.*;
import static uk.gov.ida.saml.core.test.builders.GenderAttributeBuilder_1_1.*;
import static uk.gov.ida.saml.core.test.builders.IdentityProviderAuthnStatementBuilder.*;
import static uk.gov.ida.saml.core.test.builders.MatchingDatasetBuilder.*;
import static uk.gov.ida.saml.core.test.builders.PersonNameAttributeBuilder_1_1.*;
import static uk.gov.ida.saml.core.test.builders.PersonNameAttributeValueBuilder.*;

@RunWith(OpenSAMLMockitoRunner.class)
public class IdentityProviderAssertionUnmarshallerTest {

    @Mock
    private MatchingDatasetUnmarshaller matchingDatasetUnmarshaller;

    @Mock
    private IdentityProviderAuthnStatementUnmarshaller idaAuthnStatementUnmarshaller;

    private IdentityProviderAssertionUnmarshaller unmarshaller;

    @Before
    public void setUp() throws Exception {
        unmarshaller = new IdentityProviderAssertionUnmarshaller(
                matchingDatasetUnmarshaller,
                idaAuthnStatementUnmarshaller,
                "hubEntityId");
    }

    @Test
    public void transform_shouldTransformResponseWhenNoMatchingDatasetIsPresent() throws Exception {
        Assertion originalAssertion = anAssertion().buildUnencrypted();

        IdentityProviderAssertion transformedAssertion = unmarshaller.fromAssertion(originalAssertion);
        assertThat(transformedAssertion.getMatchingDataset()).isEqualTo(Optional.empty());
    }

    @Test
    public void transform_shouldDelegateMatchingDatasetTransformationWhenAssertionContainsMatchingDataset() throws Exception {
        Attribute firstName = aPersonName_1_1().addValue(aPersonNameValue().withTo(DateTime.parse("1066-01-05")).build()).buildAsFirstname();
        Assertion assertion = aMatchingDatasetAssertion(
                firstName,
                aPersonName_1_1().buildAsMiddlename(),
                aPersonName_1_1().buildAsSurname(),
                aGender_1_1().build(),
                aDate_1_1().buildAsDateOfBirth(),
                anAddressAttribute().buildCurrentAddress(),
                anAddressAttribute().addAddress(anAddressAttributeValue().build()).buildPreviousAddress());

        MatchingDataset matchingDataset = aMatchingDataset().build();

        when(matchingDatasetUnmarshaller.fromAssertion(assertion)).thenReturn(matchingDataset);

        IdentityProviderAssertion identityProviderAssertion = unmarshaller.fromAssertion(assertion);
        verify(matchingDatasetUnmarshaller).fromAssertion(assertion);
        assertThat(identityProviderAssertion.getMatchingDataset().get()).isEqualTo(matchingDataset);
    }

    @Test
    public void transform_shouldDelegateAuthnStatementTransformationWhenAssertionContainsAuthnStatement() throws Exception {
        Assertion assertion = anAuthnStatementAssertion();
        IdentityProviderAuthnStatement authnStatement = anIdentityProviderAuthnStatement().build();

        when(idaAuthnStatementUnmarshaller.fromAssertion(assertion)).thenReturn(authnStatement);
        IdentityProviderAssertion identityProviderAssertion = unmarshaller.fromAssertion(assertion);

        verify(idaAuthnStatementUnmarshaller).fromAssertion(assertion);

        assertThat(identityProviderAssertion.getAuthnStatement().get()).isEqualTo(authnStatement);
    }

    @Test
    public void transform_shouldTransformSubjectConfirmationData() throws Exception {
        Assertion assertion = anAssertion().buildUnencrypted();
        SubjectConfirmationData subjectConfirmationData = assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData();

        final IdentityProviderAssertion identityProviderAssertion = unmarshaller.fromAssertion(assertion);

        final AssertionRestrictions assertionRestrictions = identityProviderAssertion.getAssertionRestrictions();

        assertThat(assertionRestrictions.getInResponseTo()).isEqualTo(subjectConfirmationData.getInResponseTo());
        assertThat(assertionRestrictions.getRecipient()).isEqualTo(subjectConfirmationData.getRecipient());
        assertThat(assertionRestrictions.getNotOnOrAfter()).isEqualTo(subjectConfirmationData.getNotOnOrAfter());
    }
}
