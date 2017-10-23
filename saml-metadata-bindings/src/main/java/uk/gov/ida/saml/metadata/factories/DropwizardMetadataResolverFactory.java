package uk.gov.ida.saml.metadata.factories;

import io.dropwizard.setup.Environment;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.MetadataConfiguration;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;

import javax.ws.rs.client.Client;
import java.net.URI;
import java.security.KeyStore;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;

public class DropwizardMetadataResolverFactory {
    private final MetadataResolverFactory metadataResolverFactory = new MetadataResolverFactory();
    private final ExpiredCertificateMetadataFilter expiredCertificateMetadataFilter = new ExpiredCertificateMetadataFilter();
    private final MetadataClientFactory metadataClientFactory = new MetadataClientFactory();

    public MetadataResolver createMetadataResolver(Environment environment, MetadataConfiguration metadataConfiguration) {
        return createMetadataResolver(environment, metadataConfiguration, true);
    }

    public MetadataResolver createMetadataResolverWithoutSignatureValidation(Environment environment, MetadataConfiguration metadataConfiguration) {
        return createMetadataResolver(environment, metadataConfiguration, false);
    }

    private MetadataResolver createMetadataResolver(Environment environment, MetadataConfiguration metadataConfiguration, boolean validateSignatures) {
        URI uri = metadataConfiguration.getUri();
        Long minRefreshDelay = metadataConfiguration.getMinRefreshDelay();
        Long maxRefreshDelay = metadataConfiguration.getMaxRefreshDelay();
        Client client = metadataClientFactory.getClient(environment, metadataConfiguration);

        return metadataResolverFactory.create(
            client,
            uri,
            getMetadataFilters(metadataConfiguration, validateSignatures),
            minRefreshDelay,
            maxRefreshDelay
        );
    }

    private List<MetadataFilter> getMetadataFilters(MetadataConfiguration metadataConfiguration, boolean validateSignatures) {
        if (!validateSignatures) { return emptyList(); }

        KeyStore metadataTrustStore = metadataConfiguration.getTrustStore();
        PKIXSignatureValidationFilterProvider pkixSignatureValidationFilterProvider = new PKIXSignatureValidationFilterProvider(metadataTrustStore);
        return asList(pkixSignatureValidationFilterProvider.get(), expiredCertificateMetadataFilter);
    }
}
