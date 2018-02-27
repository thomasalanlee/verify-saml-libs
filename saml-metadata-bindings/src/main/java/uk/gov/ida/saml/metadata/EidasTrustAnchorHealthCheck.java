package uk.gov.ida.saml.metadata;

import com.codahale.metrics.health.HealthCheck;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class EidasTrustAnchorHealthCheck extends HealthCheck {

    private final EidasMetadataResolverRepository metadataResolverRepository;

    @Inject
    public EidasTrustAnchorHealthCheck(EidasMetadataResolverRepository metadataResolverRepository) {
        this.metadataResolverRepository = metadataResolverRepository;
    }

    @Override
    protected Result check() throws Exception {
        HashMap<String, MetadataResolver> metadataResolvers = metadataResolverRepository.getMetadataResolvers();
        if (metadataResolvers.isEmpty()){
            return Result.unhealthy("No valid Trust Anchors found");
        }
        List<String> invalidMetadataEntityIds = new ArrayList<>();
        for (String entityId : metadataResolvers.keySet()){
            CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(entityId));
            EntityDescriptor entityDescriptor = metadataResolvers.get(entityId).resolveSingle(criteria);
            if (entityDescriptor == null){
                invalidMetadataEntityIds.add(entityId);
            }
        }
        if (!invalidMetadataEntityIds.isEmpty()){
           return Result.unhealthy("Metadata not found for following entityIds " + String.join(", ", invalidMetadataEntityIds));
        }
        return Result.healthy();
    }

}
