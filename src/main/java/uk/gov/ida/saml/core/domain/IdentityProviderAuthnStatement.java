package uk.gov.ida.saml.core.domain;

import com.google.common.base.Optional;

public final class IdentityProviderAuthnStatement {

    private Optional<FraudAuthnDetails> fraudAuthnDetails;
    private IpAddress userIpAddress;
    private AuthnContext levelOfAssurance;

    private IdentityProviderAuthnStatement(
            AuthnContext levelOfAssurance,
            Optional<FraudAuthnDetails> fraudAuthnDetails,
            IpAddress userIpAddress) {

        this.levelOfAssurance = levelOfAssurance;
        this.fraudAuthnDetails = fraudAuthnDetails;
        this.userIpAddress = userIpAddress;
    }

    public AuthnContext getAuthnContext() {
        return levelOfAssurance;
    }

    public static IdentityProviderAuthnStatement createIdentityProviderAuthnStatement(
            AuthnContext levelOfAssurance,
            IpAddress userIpAddress) {

        return new IdentityProviderAuthnStatement(levelOfAssurance, Optional.<FraudAuthnDetails>absent(), userIpAddress);
    }

    public static IdentityProviderAuthnStatement createIdentityProviderFraudAuthnStatement(
            FraudAuthnDetails fraudAuthnDetails,
            IpAddress userIpAddress) {

        return new IdentityProviderAuthnStatement(AuthnContext.LEVEL_X, Optional.fromNullable(fraudAuthnDetails), userIpAddress);
    }

    public boolean isFraudAuthnStatement() {
        return fraudAuthnDetails.isPresent();
    }

    public FraudAuthnDetails getFraudAuthnDetails() {
        return fraudAuthnDetails.orNull();
    }

    public IpAddress getUserIpAddress() {
        return userIpAddress;
    }
}
