package uk.gov.ida.saml.metadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.junit.Test;
import org.junit.runner.RunWith;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;

import javax.ws.rs.client.Client;
import java.net.URI;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(OpenSAMLMockitoRunner.class)
public class JerseyClientMetadataResolverTest {

    @Test
    public void shouldCloseAllResourcesOnDestroy() throws ComponentInitializationException {
        Client mockClient = mock(Client.class);
        JerseyClientMetadataResolver resolver = new JerseyClientMetadataResolver(null, mockClient, URI.create(""));
        resolver.setId("Stupid Test Id");
        resolver.setFailFastInitialization(false);
        resolver.initialize();

        resolver.destroy();

        assertTrue(resolver.isDestroyed());
        verify(mockClient, times(1)).close();
    }
}
