package uk.gov.ida.saml.core.transformers;

import java.util.Optional;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import uk.gov.ida.saml.core.domain.AssertionRestrictions;
import uk.gov.ida.saml.core.domain.IdentityProviderAssertion;
import uk.gov.ida.saml.core.domain.IdentityProviderAuthnStatement;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.domain.PersistentId;

public class IdentityProviderAssertionUnmarshaller {
    private final MatchingDatasetUnmarshaller matchingDatasetUnmarshaller;
    private final IdentityProviderAuthnStatementUnmarshaller identityProviderAuthnStatementUnmarshaller;
    private final String hubEntityId;

    public IdentityProviderAssertionUnmarshaller(
            MatchingDatasetUnmarshaller matchingDatasetUnmarshaller,
            IdentityProviderAuthnStatementUnmarshaller identityProviderAuthnStatementUnmarshaller,
            String hubEntityId) {
        this.matchingDatasetUnmarshaller = matchingDatasetUnmarshaller;
        this.identityProviderAuthnStatementUnmarshaller = identityProviderAuthnStatementUnmarshaller;
        this.hubEntityId = hubEntityId;
    }

    public IdentityProviderAssertion fromAssertion(Assertion assertion) {

        MatchingDataset matchingDataset = null;
        IdentityProviderAuthnStatement authnStatement = null;

        if (assertionContainsMatchingDataset(assertion)) {
            matchingDataset = this.matchingDatasetUnmarshaller.fromAssertion(assertion);
        }
        if (containsAuthnStatement(assertion) && !isCycle3AssertionFromHub(assertion)) {
            authnStatement = this.identityProviderAuthnStatementUnmarshaller.fromAssertion(assertion);
        }

        final SubjectConfirmationData subjectConfirmationData = assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData();

        AssertionRestrictions assertionRestrictions = new AssertionRestrictions(
                subjectConfirmationData.getNotOnOrAfter(),
                subjectConfirmationData.getInResponseTo(),
                subjectConfirmationData.getRecipient());

        PersistentId persistentId = new PersistentId(assertion.getSubject().getNameID().getValue());
        return new IdentityProviderAssertion(
                assertion.getID(),
                assertion.getIssuer().getValue(),
                assertion.getIssueInstant(),
                persistentId,
                assertionRestrictions,
                Optional.ofNullable(matchingDataset),
                Optional.ofNullable(authnStatement));
    }

    private boolean assertionContainsMatchingDataset(Assertion assertion) {
        // This assumes that the MDS and AuthnStatement are NOT in the same assertion
        return doesAssertionContainAttributes(assertion) && !isCycle3AssertionFromHub(assertion) && !containsAuthnStatement(assertion);
    }

    private boolean containsAuthnStatement(Assertion assertion) {
        return !assertion.getAuthnStatements().isEmpty();
    }

    private boolean doesAssertionContainAttributes(Assertion assertion) {
        return !assertion.getAttributeStatements().isEmpty();
    }

    private boolean isCycle3AssertionFromHub(Assertion assertion) {
        return assertion.getIssuer().getValue().equals(hubEntityId);
    }
}
