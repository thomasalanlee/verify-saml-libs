package uk.gov.ida.saml.core.test.builders;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.core.AuthnStatement;
import uk.gov.ida.saml.core.extensions.EidasAuthnContext;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(OpenSAMLMockitoRunner.class)
public class AuthnStatementBuilderTest {

    @Test
    public void shouldBuildWithCorretLOA() {
        AuthnStatement authnStatement = AuthnStatementBuilder.anEidasAuthnStatement().build();

        assertThat(authnStatement.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()).isEqualTo(EidasAuthnContext.EIDAS_LOA_SUBSTANTIAL);
    }

}