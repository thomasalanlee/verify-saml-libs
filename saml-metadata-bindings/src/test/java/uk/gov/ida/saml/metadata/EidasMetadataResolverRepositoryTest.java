package uk.gov.ida.saml.metadata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import net.minidev.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import io.dropwizard.setup.Environment;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EidasMetadataResolverRepositoryTest {

    @Mock
    EidasTrustAnchorResolver trustAnchorResolver;

    @Mock
    Environment environment;

    @Mock
    EidasMetadataConfiguration metadataConfiguration;

    @Mock
    DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory;

    @Mock
    Timer timer;

    @Mock
    MetadataResolver metadataResolver;

    private EidasMetadataResolverRepository metadataResolverRepository;

    @Before
    public void setUp() throws URISyntaxException {
        when(metadataConfiguration.getMetadataBaseUri()).thenReturn(new URI("http://example.com"));
        when(dropwizardMetadataResolverFactory.createMetadataResolver(eq(environment), any())).thenReturn(metadataResolver);
    }

    @Test
    public void shouldCreateMetadataResolverWhenTrustAnchorIsValid() throws ParseException, JOSEException, SignatureException, CertificateException {
        List<JWK> trustAnchors = Arrays.asList(createJWK("entity-id", TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT));
        when(trustAnchorResolver.getTrustAnchors()).thenReturn(trustAnchors);
        metadataResolverRepository = new EidasMetadataResolverRepository(trustAnchorResolver, environment, metadataConfiguration, dropwizardMetadataResolverFactory, timer);

        MetadataResolver createdMetadataResolver = metadataResolverRepository.getMetadataResolver(trustAnchors.get(0).getKeyID());

        assertThat(createdMetadataResolver).isEqualTo(metadataResolver);
    }

    @Test
    public void shouldNotCreateMetadataResolverWhenCertificateIsInvalid() throws ParseException, SignatureException, JOSEException, CertificateException {
        List<JWK> trustAnchors = Arrays.asList(createJWK("entity-id", TestCertificateStrings.UNCHAINED_PUBLIC_CERT));
        when(trustAnchorResolver.getTrustAnchors()).thenReturn(trustAnchors);
        metadataResolverRepository = new EidasMetadataResolverRepository(trustAnchorResolver, environment, metadataConfiguration, dropwizardMetadataResolverFactory, timer);

        MetadataResolver createdMetadataResolver = metadataResolverRepository.getMetadataResolver("entity-id");
        assertThat(createdMetadataResolver).isNull();
    }

    @Test
    public void shouldUpdateListOfMetadataResolversWhenRefreshing() throws ParseException, SignatureException, JOSEException, CertificateException {
        List<JWK> trustAnchors = new ArrayList<>();
        trustAnchors.add(createJWK("entity-id", TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT));

        when(trustAnchorResolver.getTrustAnchors()).thenReturn(trustAnchors);
        metadataResolverRepository = new EidasMetadataResolverRepository(trustAnchorResolver, environment, metadataConfiguration, dropwizardMetadataResolverFactory, timer);

        trustAnchors.remove(0);
        trustAnchors.add(createJWK("entity-id-1", TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT));

        ArgumentCaptor<TimerTask> argumentCaptor = ArgumentCaptor.forClass(TimerTask.class);
        verify(timer).schedule(argumentCaptor.capture(), anyLong());
        TimerTask value = argumentCaptor.getValue();
        value.run();

        assertThat(metadataResolverRepository.getMetadataResolver("entity-id")).isNull();
        assertThat(metadataResolverRepository.getMetadataResolver("entity-id-1")).isNotNull();
    }

    private JWK createJWK(String entityId, String certificate) throws ParseException {
        RSAPublicKey publicKey = (RSAPublicKey) new X509CertificateFactory().createCertificate(certificate).getPublicKey();

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("kty", "RSA");
        jsonObject.put("key_ops", Collections.singletonList("verify"));
        jsonObject.put("kid", entityId);
        jsonObject.put("alg", "RS256");
        jsonObject.put("e", new String (Base64.encodeInteger(publicKey.getPublicExponent())));
        jsonObject.put("n", new String (Base64.encodeInteger(publicKey.getModulus())));
        jsonObject.put("x5c", Collections.singletonList(certificate));

        return JWK.parse(jsonObject.toJSONString());
    }
}
