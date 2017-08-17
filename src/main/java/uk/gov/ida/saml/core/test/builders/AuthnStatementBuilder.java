package uk.gov.ida.saml.core.test.builders;

import com.google.common.base.Optional;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnStatement;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

import static com.google.common.base.Optional.fromNullable;

public class AuthnStatementBuilder {

    private static OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();

    private Optional<AuthnContext> authnContext = fromNullable(AuthnContextBuilder.anAuthnContext().build());

    public static AuthnStatementBuilder anAuthnStatement() {
        return new AuthnStatementBuilder();
    }

    public AuthnStatement build() {
        AuthnStatement authnStatement = openSamlXmlObjectFactory.createAuthnStatement();

        if (authnContext.isPresent()) {
            authnStatement.setAuthnContext(authnContext.get());
        }

        return authnStatement;
    }

    public AuthnStatementBuilder withAuthnContext(AuthnContext authnContext) {
        this.authnContext = fromNullable(authnContext);
        return this;
    }

    public AuthnStatementBuilder withId(String s) {
        throw new UnsupportedOperationException("Implement Me!");
    }
}
