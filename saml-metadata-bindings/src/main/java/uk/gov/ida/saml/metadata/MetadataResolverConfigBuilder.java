package uk.gov.ida.saml.metadata;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import org.joda.time.DateTime;
import uk.gov.ida.saml.metadata.exception.TrustAnchorConfigException;

import javax.ws.rs.core.UriBuilder;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import static uk.gov.ida.saml.metadata.ResourceEncoder.entityIdAsResource;

public class MetadataResolverConfigBuilder {

    public MetadataResolverConfiguration createMetadataResolverConfiguration(JWK trustAnchor, EidasMetadataConfiguration configuration)
            throws CertificateException, UnsupportedEncodingException {
        return new TrustStoreBackedMetadataConfiguration(
                fullUri(configuration.getMetadataSourceUri(), trustAnchor.getKeyID()),
                configuration.getMinRefreshDelay(),
                configuration.getMaxRefreshDelay(),
                null,
                configuration.getJerseyClientConfiguration(),
                getClientName(trustAnchor.getKeyID(), configuration.getJerseyClientName()),
                null,
                trustStoreConfig(trustAnchor));
    }

    private URI fullUri(URI sourceUri, String entityId) throws UnsupportedEncodingException {
        return UriBuilder
                .fromUri(sourceUri)
                .path(entityIdAsResource(entityId))
                .build();
    }

    private String getClientName(String entityId, String clientName) {
        return String.format("%s - %s - %s",
                clientName,
                entityId,
                DateTime.now().getMillis());
    }

    private DynamicTrustStoreConfiguration trustStoreConfig(JWK trustAnchor) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = trustAnchor.getX509CertChain()
                .stream()
                .map(Base64::decode)
                .map(ByteArrayInputStream::new)
                .map(certStream -> {
                    try { //Java streams don't allow throwing checked exceptions
                        return (X509Certificate) certificateFactory.generateCertificate(certStream);
                    } catch (CertificateException e) {
                        throw new TrustAnchorConfigException("Certificate in Trust Anchor x5c is not a valid x509", e);
                    }
                })
                .collect(Collectors.toList());

        return new DynamicTrustStoreConfiguration(buildKeyStoreFromCertificate(certs));
    }

    private KeyStore buildKeyStoreFromCertificate(List<X509Certificate> certificates) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            for(X509Certificate certificate : certificates) {
                keyStore.setCertificateEntry("certificate-" + certificates.indexOf(certificate), certificate);
            }
            return keyStore;
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            throw new TrustAnchorConfigException("Unable to build key store", e);
        }
    }
}
