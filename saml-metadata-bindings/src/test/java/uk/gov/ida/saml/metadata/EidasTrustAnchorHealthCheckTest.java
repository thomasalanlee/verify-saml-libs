package uk.gov.ida.saml.metadata;

import com.codahale.metrics.health.HealthCheck;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.saml.core.test.builders.metadata.EntityDescriptorBuilder;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EidasTrustAnchorHealthCheckTest {

    @Mock
    EidasMetadataResolverRepository metadataResolverRepository;

    private EidasTrustAnchorHealthCheck eidasTrustAnchorHealthCheck;

    @Before
    public void setUp(){
        eidasTrustAnchorHealthCheck = new EidasTrustAnchorHealthCheck(metadataResolverRepository);
    }

    @Test
    public void shouldReturnUnhealthyWhenNoTrustAnchorsAreFound() throws Exception {
        when(metadataResolverRepository.getMetadataResolvers()).thenReturn(new HashMap<>());

        HealthCheck.Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isFalse();
    }

    @Test
    public void shouldReturnUnhealthyWhenAnyMetadataResolversDontContainMetadataMatchingTheEntityId() throws Exception {
        String entityId1 = "entityId1";
        String entityId2 = "entityId2";
        String entityId3 = "entityId3";
        MetadataResolver metadataResolver1 = getValidMetadataResolver(entityId1);
        MetadataResolver metadataResolver2 = mock(MetadataResolver.class);
        MetadataResolver metadataResolver3 = mock(MetadataResolver.class);
        HashMap<String, MetadataResolver> metadataResolverHashMap = new HashMap<>();
        metadataResolverHashMap.put(entityId1, metadataResolver1);
        metadataResolverHashMap.put(entityId2, metadataResolver2);
        metadataResolverHashMap.put(entityId3, metadataResolver3);

        when(metadataResolverRepository.getMetadataResolvers()).thenReturn(metadataResolverHashMap);

        HealthCheck.Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isFalse();
        assertThat(result.getMessage()).contains(entityId2, entityId3);
        assertThat(result.getMessage()).doesNotContain(entityId1);
    }

    @Test
    public void shouldReturnHealthyWhenAllMetadataResolversAreHealthy() throws Exception {
        String entityId1 = "entityId1";
        String entityId2 = "entityId2";
        MetadataResolver metadataResolver1 = getValidMetadataResolver(entityId1);
        MetadataResolver metadataResolver2 = getValidMetadataResolver(entityId2);
        HashMap<String, MetadataResolver> metadataResolverHashMap = new HashMap<>();
        metadataResolverHashMap.put(entityId1, metadataResolver1);
        metadataResolverHashMap.put(entityId2, metadataResolver2);

        when(metadataResolverRepository.getMetadataResolvers()).thenReturn(metadataResolverHashMap);

        HealthCheck.Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isTrue();
    }

    private MetadataResolver getValidMetadataResolver(String entityId) throws MarshallingException, SignatureException, ResolverException {
        MetadataResolver metadataResolver = mock(MetadataResolver.class);
        when(metadataResolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityId)))).thenReturn(EntityDescriptorBuilder.anEntityDescriptor().build());

        return metadataResolver;
    }
}
