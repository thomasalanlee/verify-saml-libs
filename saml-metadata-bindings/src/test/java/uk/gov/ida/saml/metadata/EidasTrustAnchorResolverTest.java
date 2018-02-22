package uk.gov.ida.saml.metadata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import net.minidev.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import uk.gov.ida.common.shared.security.PrivateKeyFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;
import uk.gov.ida.eidas.trustanchor.Generator;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EidasTrustAnchorResolverTest {

    private EidasTrustAnchorResolver eidasTrustAnchorResolver;

    @Mock
    private Client client;

    @Mock
    private WebTarget webTarget;

    @Mock
    private Invocation.Builder builder;

    @Mock
    private PrivateKey privateSigningKey;

    @Mock
    private PublicKey publicSigningKey;

    @Mock
    private Response trustAnchorResponse;

    @Mock
    private CertificateChainValidator certificateChainValidator;
    
    @Before
    public void setUp() throws IOException, NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, URISyntaxException, ParseException, JOSEException {

        URI uri = new URI("https://govukverify-trust-anchor-dev.s3.amazonaws.com/devTrustAnchor");
        privateSigningKey = new PrivateKeyFactory().createPrivateKey(Base64.decodeBase64(TestCertificateStrings.UNCHAINED_PRIVATE_KEY));
        X509Certificate publicSigningCert = new X509CertificateFactory().createCertificate(TestCertificateStrings.UNCHAINED_PUBLIC_CERT);
        publicSigningKey = publicSigningCert.getPublicKey();

//        eidasTrustAnchorResolver = new EidasTrustAnchorResolver(uri, client, publicSigningCert, certificateChainValidator);
        eidasTrustAnchorResolver = new EidasTrustAnchorResolver(uri, new JerseyClientBuilder().build(), publicSigningCert, certificateChainValidator);
        when(client.target(uri)).thenReturn(webTarget);
        when(webTarget.request()).thenReturn(builder);
        when(builder.get()).thenReturn(trustAnchorResponse);
    }

    @Test
    public void shouldReturnTrustAnchorsIfResponseIsValid() throws ParseException, SignatureException, JOSEException {
        when(trustAnchorResponse.readEntity(String.class)).thenReturn(createJwsWithACountryTrustAnchor(privateSigningKey));

        List<JWK> result = eidasTrustAnchorResolver.getTrustAnchors();

        assertThat(result.size()).isEqualTo(1);
        assertThat(result.get(0).getKeyID()).isEqualTo("https://eu.entity.id");
    }

    @Test
    public void shouldThrowSignatureExceptionIfResponseIsNotSignedWithExpectedKey() throws ParseException, JOSEException {
        PrivateKey unexpectedPrivateKey = new PrivateKeyFactory().createPrivateKey(Base64.decodeBase64(TestCertificateStrings.TEST_PRIVATE_KEY));
        when(trustAnchorResponse.readEntity(String.class)).thenReturn(createJwsWithACountryTrustAnchor(unexpectedPrivateKey));

        assertThatThrownBy(() -> eidasTrustAnchorResolver.getTrustAnchors()).isInstanceOf(SignatureException.class);
    }

    private String createJwsWithACountryTrustAnchor(PrivateKey privateKey) throws ParseException, JOSEException {
        Generator generator = new Generator(privateKey);
        return generator.generate(Arrays.asList(createJsonAnchor("https://eu.entity.id")));
    }

    private String createJsonAnchor(String kid){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("kty", "RSA");
        jsonObject.put("key_ops", Collections.singletonList("verify"));
        jsonObject.put("kid", kid);
        jsonObject.put("alg", "RS256");
        jsonObject.put("e", new String (Base64.encodeInteger(((RSAPublicKey) publicSigningKey).getPublicExponent())));
        jsonObject.put("n", new String (Base64.encodeInteger(((RSAPublicKey) publicSigningKey).getModulus())));
        jsonObject.put("x5c", Collections.singletonList(TestCertificateStrings.UNCHAINED_PUBLIC_CERT));

        return jsonObject.toJSONString();
    }
}
