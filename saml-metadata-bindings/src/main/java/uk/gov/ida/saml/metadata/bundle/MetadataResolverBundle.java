package uk.gov.ida.saml.metadata.bundle;

import com.google.inject.Module;
import io.dropwizard.Configuration;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.factories.CredentialResolverFactory;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;
import uk.gov.ida.saml.metadata.factories.MetadataSignatureTrustEngineFactory;

import javax.annotation.Nullable;
import javax.inject.Provider;

public class MetadataResolverBundle<T extends Configuration> implements io.dropwizard.ConfiguredBundle<T> {
    private final MetadataConfigurationExtractor<T> configExtractor;
    private MetadataResolver metadataResolver;
    private DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory = new DropwizardMetadataResolverFactory();
    private ExplicitKeySignatureTrustEngine signatureTrustEngine;
    private MetadataCredentialResolver credentialResolver;
    private final boolean validateSignatures;

    public MetadataResolverBundle(MetadataConfigurationExtractor<T> configExtractor) {
        this(configExtractor, true);
    }

    public MetadataResolverBundle(MetadataConfigurationExtractor<T> configExtractor, boolean validateSignatures) {
        this.configExtractor = configExtractor;
        this.validateSignatures = validateSignatures;
    }

    @Override
    public void run(T configuration, Environment environment) throws Exception {
        MetadataResolverConfiguration metadataConfiguration = configExtractor.getMetadataConfiguration(configuration);
        metadataResolver = dropwizardMetadataResolverFactory.createMetadataResolver(environment, metadataConfiguration, validateSignatures);
        signatureTrustEngine = new MetadataSignatureTrustEngineFactory().createSignatureTrustEngine(metadataResolver);
        credentialResolver = new CredentialResolverFactory().create(metadataResolver);
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

}
