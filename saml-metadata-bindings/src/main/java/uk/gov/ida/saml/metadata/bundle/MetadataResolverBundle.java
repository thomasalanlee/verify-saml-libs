package uk.gov.ida.saml.metadata.bundle;

import com.google.inject.Module;
import io.dropwizard.Configuration;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.TrustStoreConfiguration;
import uk.gov.ida.saml.metadata.factories.CredentialResolverFactory;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;
import uk.gov.ida.saml.metadata.factories.MetadataSignatureTrustEngineFactory;

import javax.annotation.Nullable;
import javax.inject.Provider;

public class MetadataResolverBundle<T extends Configuration> implements io.dropwizard.ConfiguredBundle<T> {
    private final MetadataConfigurationExtractor<T> metadataConfigurationExtractor;
    private final HubConfigurationExtractor<T> hubConfigurationExtractor;
    private final IdpConfigurationExtractor<T> idpConfigurationExtractor;
    private MetadataResolver metadataResolver;
    private DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory = new DropwizardMetadataResolverFactory();
    private ExplicitKeySignatureTrustEngine signatureTrustEngine;
    private MetadataCredentialResolver credentialResolver;
    private final boolean validateSignatures;

    public MetadataResolverBundle(
        MetadataConfigurationExtractor<T> metadataConfigExtractor,
        HubConfigurationExtractor<T> hubConfigurationExtractor,
        IdpConfigurationExtractor<T> idpConfigurationExtractor
        ) {

        this(metadataConfigExtractor, hubConfigurationExtractor, idpConfigurationExtractor, true);
    }

    public MetadataResolverBundle(
        MetadataConfigurationExtractor<T> metadataConfigurationExtractor,
        HubConfigurationExtractor<T> hubConfigurationExtractor,
        IdpConfigurationExtractor<T> idpConfigurationExtractor,
        boolean validateSignatures) {
        this.metadataConfigurationExtractor = metadataConfigurationExtractor;
        this.hubConfigurationExtractor = hubConfigurationExtractor;
        this.idpConfigurationExtractor = idpConfigurationExtractor;
        this.validateSignatures = validateSignatures;
    }

    @Override
    public void run(T configuration, Environment environment) throws Exception {
        MetadataResolverConfiguration metadataConfiguration = metadataConfigurationExtractor.getMetadataConfiguration(configuration);
        TrustStoreConfiguration hubTrustStoreConfiguration = hubConfigurationExtractor.getHubTrustStoreConfiguration(configuration);
        TrustStoreConfiguration idpTrustStoreConfiguration = idpConfigurationExtractor.getIdpTrustStoreConfiguration(configuration);
        metadataResolver = dropwizardMetadataResolverFactory.createMetadataResolver(
            environment,
            metadataConfiguration,
            validateSignatures,
            hubTrustStoreConfiguration,
            idpTrustStoreConfiguration);
        signatureTrustEngine = new MetadataSignatureTrustEngineFactory().createSignatureTrustEngine(metadataResolver);
        credentialResolver = new CredentialResolverFactory().create(metadataResolver);
    }

    @Override
    public void initialize(Bootstrap<?> bootstrap) {
        //NOOP
    }

    @Nullable
    public MetadataResolver getMetadataResolver() {
        return metadataResolver;
    }

    public Provider<MetadataResolver> getMetadataResolverProvider() {
        return () -> metadataResolver;
    }

    @Nullable
    public ExplicitKeySignatureTrustEngine getSignatureTrustEngine() {
        return signatureTrustEngine;
    }

    public Provider<ExplicitKeySignatureTrustEngine> getSignatureTrustEngineProvider() {
        return () -> signatureTrustEngine;
    }

    @Nullable
    public MetadataCredentialResolver getMetadataCredentialResolver() {
        return credentialResolver;
    }

    public Provider<MetadataCredentialResolver> getMetadataCredentialResolverProvider() {
        return () -> credentialResolver;
    }


    public Module getMetadataModule() {
      return binder -> binder.bind(MetadataResolver.class).toProvider(getMetadataResolverProvider());
    }

    public interface MetadataConfigurationExtractor<T> {
        MetadataResolverConfiguration getMetadataConfiguration(T configuration);
    }

    public interface HubConfigurationExtractor<T> {
        TrustStoreConfiguration getHubTrustStoreConfiguration(T configuration);
    }

    public interface IdpConfigurationExtractor<T> {
        TrustStoreConfiguration getIdpTrustStoreConfiguration(T configuration);
    }
}
