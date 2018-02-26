package uk.gov.ida.saml.metadata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import net.minidev.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import io.dropwizard.setup.Environment;
import uk.gov.ida.common.shared.security.PublicKeyFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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

    private EidasMetadataResolverRepository metadataResolverRepository;

    @Before
    public void setUp() throws ParseException, JOSEException, SignatureException {
    }

    @Test
    public void schedulesRegularUpdatesOfTheTrustAnchor() throws ParseException, JOSEException, SignatureException {
        List<JWK> trustAnchors = Arrays.asList(createJWK());
        when(trustAnchorResolver.getTrustAnchors()).thenReturn(trustAnchors);

        metadataResolverRepository = new EidasMetadataResolverRepository(trustAnchorResolver, environment, metadataConfiguration);

    }

    private JWK createJWK() throws ParseException {
        RSAPublicKey publicKey = (RSAPublicKey) new PublicKeyFactory(new X509CertificateFactory()).createPublicKey(TestCertificateStrings.UNCHAINED_PUBLIC_CERT);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("kty", "RSA");
        jsonObject.put("key_ops", Collections.singletonList("verify"));
        jsonObject.put("kid", "entity-id");
        jsonObject.put("alg", "RS256");
        jsonObject.put("e", new String (Base64.encodeInteger(publicKey.getPublicExponent())));
        jsonObject.put("n", new String (Base64.encodeInteger(publicKey.getModulus())));
        jsonObject.put("x5c", Collections.singletonList(TestCertificateStrings.UNCHAINED_PUBLIC_CERT));

        return JWK.parse(jsonObject.toJSONString());
    }
}