package uk.gov.ida.saml.core.domain;

import com.google.common.base.Optional;
import org.joda.time.DateTime;

public class IdentityProviderAssertion extends OutboundAssertion {
    private Optional<MatchingDataset> matchingDataset = Optional.absent();
    private Optional<IdentityProviderAuthnStatement> authnStatement = Optional.absent();

    public IdentityProviderAssertion(
            String id,
            String issuerId,
            DateTime issueInstant,
            PersistentId persistentId,
            AssertionRestrictions assertionRestrictions,
            Optional<MatchingDataset> matchingDataset,
            Optional<IdentityProviderAuthnStatement> authnStatement) {

        super(id, issuerId, issueInstant, persistentId, assertionRestrictions);

        this.matchingDataset = matchingDataset;
        this.authnStatement = authnStatement;
    }

    public Optional<MatchingDataset> getMatchingDataset() {
        return matchingDataset;
    }

    public Optional<IdentityProviderAuthnStatement> getAuthnStatement(){
        return authnStatement;
    }
}
