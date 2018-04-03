package uk.gov.ida.saml.metadata.bundle;

import com.google.inject.Module;
import io.dropwizard.Configuration;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;

import javax.inject.Provider;

public class MetadataResolverBundle<T extends Configuration> implements io.dropwizard.ConfiguredBundle<T> {
    private MetadataConfigurationExtractor<T> configExtractor;
    private MetadataResolver metadataResolver;
    private DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory = new DropwizardMetadataResolverFactory();

    public MetadataResolverBundle(MetadataConfigurationExtractor<T> configExtractor) {
        this.configExtractor = configExtractor;
    }

    @Override
    public void run(T configuration, Environment environment) throws Exception {
        MetadataResolverConfiguration metadataConfiguration = configExtractor.getMetadataConfiguration(configuration);
        metadataResolver = dropwizardMetadataResolverFactory.createMetadataResolver(environment, metadataConfiguration);
    }

    @Override
    public void initialize(Bootstrap<?> bootstrap) {
        //NOOP
    }

    public MetadataResolver getMetadataResolver() {
        return metadataResolver;
    }

    public Provider<MetadataResolver> getMetadataResolverProvider() {
        return () -> metadataResolver;
    }

    public Module getMetadataModule() {
      return binder -> binder.bind(MetadataResolver.class).toProvider(getMetadataResolverProvider());
    }

    public interface MetadataConfigurationExtractor<T> {
        MetadataResolverConfiguration getMetadataConfiguration(T configuration);
    }

}
