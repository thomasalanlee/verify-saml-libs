import com.nimbusds.jose.jwk.JWK;
import org.junit.Test;
import uk.gov.ida.saml.metadata.EidasMetadataConfiguration;
import uk.gov.ida.saml.metadata.MetadataResolverConfigBuilder;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;

import javax.ws.rs.core.UriBuilder;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MetadataResolverConfigBuilderTest {

    private final MetadataResolverConfigBuilder testBuilder = new MetadataResolverConfigBuilder();
    private final JWK mockTrustAnchor = mock(JWK.class);
    private final EidasMetadataConfiguration mockConfiguration = mock(EidasMetadataConfiguration.class);

    @Test
    public void shouldConcatenateMetadataSourceUriAndMetadataEntityIdIntoEncodedFullUri() throws CertificateException, UnsupportedEncodingException {
        when(mockTrustAnchor.getKeyID()).thenReturn("https://example.com/ServiceMetadata");

        when(mockConfiguration.getMetadataSourceUri()).thenReturn(UriBuilder.fromUri("https://source.com").build());

        MetadataResolverConfiguration metadataResolverConfiguration =
                testBuilder.createMetadataResolverConfiguration(mockTrustAnchor, mockConfiguration);
        URI targetUri = UriBuilder.fromUri("https://source.com/https%253A%252F%252Fexample.com%252FServiceMetadata").build();
        assertThat(metadataResolverConfiguration.getUri()).isEqualTo(targetUri);
    }
}
