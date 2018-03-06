package uk.gov.ida.saml.core.domain;

import org.joda.time.DateTime;

import java.net.URI;
import java.util.Optional;

public class OutboundResponseFromHub extends IdaSamlResponse {

    private Optional<String> matchingServiceAssertion;
    private TransactionIdaStatus status;

    public OutboundResponseFromHub(
            String responseId,
            String inResponseTo,
            String issuer,
            DateTime issueInstant,
            TransactionIdaStatus status,
            Optional<String> matchingServiceAssertion,
            URI destination) {

        super(responseId, issueInstant, inResponseTo, issuer, destination);
        this.matchingServiceAssertion = matchingServiceAssertion;
        this.status = status;
    }

    public Optional<String> getMatchingServiceAssertion() {
        return matchingServiceAssertion;
    }

    public TransactionIdaStatus getStatus() {
        return status;
    }
}
