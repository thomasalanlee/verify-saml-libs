package uk.gov.ida.saml.metadata;

import com.codahale.metrics.health.HealthCheck.Result;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EidasTrustAnchorHealthCheckTest {

    @Mock
    EidasMetadataResolverRepository metadataResolverRepository;

    private EidasTrustAnchorHealthCheck eidasTrustAnchorHealthCheck;

    private HashMap<String, MetadataResolver> metadataResolverHashMap;
    private List<String> trustAnchorEntityIds;

    @Before
    public void setUp(){
        eidasTrustAnchorHealthCheck = new EidasTrustAnchorHealthCheck(metadataResolverRepository);

        metadataResolverHashMap = new HashMap<>();
        when(metadataResolverRepository.getMetadataResolvers()).thenReturn(metadataResolverHashMap);

        trustAnchorEntityIds = new ArrayList<>();
        when(metadataResolverRepository.getTrustAnchorsEntityIds()).thenReturn(trustAnchorEntityIds);
    }

    @Test
    public void shouldReturnUnhealthyWhenNoTrustAnchorsAreFound() throws Exception {
        Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isFalse();
    }

    @Test
    public void shouldReturnUnhealthyWhenAnyMetadataResolversDontContainMetadataMatchingTheEntityId() throws Exception {
        String entityId1 = "entityId1";
        String entityId2 = "entityId2";
        String entityId3 = "entityId3";
        trustAnchorEntityIds.addAll(Arrays.asList(entityId1, entityId2, entityId3));
        metadataResolverHashMap.put(entityId1, getValidMetadataResolver(entityId1));
        metadataResolverHashMap.put(entityId2, mock(MetadataResolver.class));
        metadataResolverHashMap.put(entityId3, mock(MetadataResolver.class));

        Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isFalse();
        assertThat(result.getMessage()).contains(entityId2, entityId3);
        assertThat(result.getMessage()).doesNotContain(entityId1);
    }

    @Test
    public void shouldReturnUnhealthyMetadataResolversAreMissing() throws Exception {
        String entityId1 = "entityId1";
        String entityId2 = "entityId2";
        String entityId3 = "entityId3";
        trustAnchorEntityIds.add(entityId1);
        trustAnchorEntityIds.add(entityId2);
        trustAnchorEntityIds.add(entityId3);
        metadataResolverHashMap.put(entityId1, getValidMetadataResolver(entityId1));

        Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isFalse();
        assertThat(result.getMessage()).contains(entityId2, entityId3);
        assertThat(result.getMessage()).doesNotContain(entityId1);
    }

    @Test
    public void shouldReturnHealthyWhenAllMetadataResolversAreHealthy() throws Exception {
        String entityId1 = "entityId1";
        String entityId2 = "entityId2";
        trustAnchorEntityIds.add(entityId1);
        trustAnchorEntityIds.add(entityId2);
        metadataResolverHashMap.put(entityId1, getValidMetadataResolver(entityId1));
        metadataResolverHashMap.put(entityId2, getValidMetadataResolver(entityId2));

        Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isTrue();
    }

    private MetadataResolver getValidMetadataResolver(String entityId) throws MarshallingException, SignatureException, ResolverException {
        MetadataResolver metadataResolver = mock(MetadataResolver.class);
        when(metadataResolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityId)))).thenReturn(EntityDescriptorBuilder.anEntityDescriptor().build());

        return metadataResolver;
    }
}
