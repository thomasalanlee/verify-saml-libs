package uk.gov.ida.saml.metadata.factories;

import io.dropwizard.setup.Environment;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;
import uk.gov.ida.common.shared.security.verification.PKIXParametersProvider;
import uk.gov.ida.saml.metadata.CertificateChainValidationFilter;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;

import javax.ws.rs.client.Client;
import java.net.URI;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static uk.gov.ida.saml.metadata.Role.IDP;
import static uk.gov.ida.saml.metadata.Role.SP;

public class DropwizardMetadataResolverFactory {
    private final MetadataResolverFactory metadataResolverFactory = new MetadataResolverFactory();
    private final ExpiredCertificateMetadataFilter expiredCertificateMetadataFilter = new ExpiredCertificateMetadataFilter();
    private final MetadataClientFactory metadataClientFactory = new MetadataClientFactory();
    private final CertificateChainValidator certificateChainValidator = new CertificateChainValidator(new PKIXParametersProvider(), new X509CertificateFactory());

    public MetadataResolver createMetadataResolver(Environment environment, MetadataResolverConfiguration metadataConfiguration) {
        return createMetadataResolver(environment, metadataConfiguration, true);
    }

    public MetadataResolver createMetadataResolverWithoutSignatureValidation(Environment environment, MetadataResolverConfiguration metadataConfiguration) {
        return createMetadataResolver(environment, metadataConfiguration, false);
    }

    public MetadataResolver createMetadataResolver(
        final Environment environment,
        final MetadataResolverConfiguration metadataConfiguration,
        final boolean validateSignatures) {

        URI uri = metadataConfiguration.getUri();
        Long minRefreshDelay = metadataConfiguration.getMinRefreshDelay();
        Long maxRefreshDelay = metadataConfiguration.getMaxRefreshDelay();
        Client client = metadataClientFactory.getClient(environment, metadataConfiguration);

        return metadataResolverFactory.create(
            client,
            uri,
            getMetadataFilters(
                metadataConfiguration,
                validateSignatures,
                Optional.ofNullable(metadataConfiguration.getHubTrustStore()),
                Optional.ofNullable(metadataConfiguration.getIdpTrustStore())),
            minRefreshDelay,
            maxRefreshDelay
        );
    }

    private List<MetadataFilter> getMetadataFilters(MetadataResolverConfiguration metadataConfiguration, boolean validateSignatures) {

        return getMetadataFilters(metadataConfiguration, validateSignatures, Optional.empty(), Optional.empty());
    }

    private List<MetadataFilter> getMetadataFilters(
        final MetadataResolverConfiguration metadataConfiguration,
        final boolean validateSignatures,
        final Optional<KeyStore> hubTrustStore,
        final Optional<KeyStore> idpTrustStore) {

        if (!validateSignatures) { return emptyList(); }

        KeyStore metadataTrustStore = metadataConfiguration.getTrustStore();
        PKIXSignatureValidationFilterProvider pkixSignatureValidationFilterProvider = new PKIXSignatureValidationFilterProvider(metadataTrustStore);

        ArrayList<MetadataFilter> metadataFilters = new ArrayList();
        metadataFilters.add(pkixSignatureValidationFilterProvider.get());
        metadataFilters.add(expiredCertificateMetadataFilter);

        hubTrustStore.ifPresent(
            hubKeyStore ->
                metadataFilters.add(new CertificateChainValidationFilter(
                    SP,
                    certificateChainValidator,
                    hubKeyStore)));

        idpTrustStore.ifPresent(
            idpKeyStore ->
                metadataFilters.add(new CertificateChainValidationFilter(
                    IDP,
                    certificateChainValidator,
                    idpKeyStore)));

        return Collections.unmodifiableList(new ArrayList(metadataFilters));
    }
}
