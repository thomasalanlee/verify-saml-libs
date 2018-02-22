package uk.gov.ida.saml.metadata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;
import net.minidev.json.JSONObject;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;

public class EidasTrustAnchorResolver {

    private final URI trustAnchorUri;
    private final Client client;
    private X509Certificate signingCertificate;
    private CertificateChainValidator certificateChainValidator;

    public EidasTrustAnchorResolver(URI trustAnchorUri, Client client, X509Certificate signingCertificate, CertificateChainValidator certificateChainValidator) {
        this.trustAnchorUri = trustAnchorUri;
        this.client = client;
        this.signingCertificate = signingCertificate;
        this.certificateChainValidator = certificateChainValidator;
    }

    public List<JWK> getTrustAnchors() throws JOSEException, SignatureException, ParseException {
        Response response = client.target(trustAnchorUri).request().get();
        String encodedJwsObject = response.readEntity(String.class);
        JWSObject trustAnchorMetadata = JWSObject.parse(encodedJwsObject);
        validateSignature(trustAnchorMetadata);
        JSONObject jsonObject = trustAnchorMetadata.getPayload().toJSONObject();
        return JWKSet.parse(jsonObject).getKeys();
    }

    private void validateSignature(JWSObject jwsObject) throws JOSEException, SignatureException {
        JWSVerifier jwsVerifier = new RSASSAVerifier(RSAKey.parse(signingCertificate));
        boolean isValid = jwsObject.verify(jwsVerifier);
        if (!isValid){
            throw new SignatureException("Trust anchor not signed with expected key. Configured trusted certificate: " + signingCertificate.getSubjectX500Principal().getName());
        }
    }

}
