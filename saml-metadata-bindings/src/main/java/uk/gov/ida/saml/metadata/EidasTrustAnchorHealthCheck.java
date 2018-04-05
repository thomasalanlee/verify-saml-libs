package uk.gov.ida.saml.metadata;

import com.codahale.metrics.health.HealthCheck;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class EidasTrustAnchorHealthCheck extends HealthCheck {

    private final EidasMetadataResolverRepository metadataResolverRepository;

    @Inject
    public EidasTrustAnchorHealthCheck(EidasMetadataResolverRepository metadataResolverRepository) {
        this.metadataResolverRepository = metadataResolverRepository;
    }

    @Override
    protected Result check() {
        List<String> trustAnchorEntityIds = metadataResolverRepository.getTrustAnchorsEntityIds();
        if (trustAnchorEntityIds.isEmpty()){
            return Result.unhealthy("No trust anchors found");
        }

        List<String> errors = new ArrayList<>();
        errors.addAll(getErrorsCreatingMetadataResolvers(trustAnchorEntityIds));
        errors.addAll(getErrorsResolvingMetadata());

        if (errors.isEmpty()) {
            return Result.healthy();
        }
        return Result.unhealthy(String.join(". ", errors));
    }

    private List<String> getErrorsCreatingMetadataResolvers(List<String> trustAnchorEntityIds) {
        List<String> entityIdsWithResolver = metadataResolverRepository.getEntityIdsWithResolver();

        if (trustAnchorEntityIds.size() > entityIdsWithResolver.size()) {
            List<String> missingMetadataResolverEntityIds = new ArrayList<>(trustAnchorEntityIds);
            missingMetadataResolverEntityIds.removeAll(entityIdsWithResolver);

            return Collections.singletonList("Metadata Resolver(s) not created for: " + String.join(", ", missingMetadataResolverEntityIds));
        }
        return Collections.emptyList();
    }

    private List<String> getErrorsResolvingMetadata() {
        List<String> errors = new ArrayList<>();
        for (String entityId : metadataResolverRepository.getEntityIdsWithResolver()) {
            try {
                CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(entityId));
                EntityDescriptor entityDescriptor = metadataResolverRepository.getMetadataResolver(entityId).resolveSingle(criteria);
                if (entityDescriptor == null){
                    errors.add("Could not resolve metadata for " + entityId);
                }
            } catch (ResolverException e) {
                errors.add(String.format("Exception thrown resolving metadata for %s - %s ", entityId, e.getMessage()));
            }
        }
        return errors;
    }
}
