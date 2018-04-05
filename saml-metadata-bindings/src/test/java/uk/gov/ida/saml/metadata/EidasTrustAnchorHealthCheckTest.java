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
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EidasTrustAnchorHealthCheckTest {

    @Mock
    private EidasMetadataResolverRepository metadataResolverRepository;

    private EidasTrustAnchorHealthCheck eidasTrustAnchorHealthCheck;

    private List<String> trustAnchorEntityIds;

    @Before
    public void setUp(){
        eidasTrustAnchorHealthCheck = new EidasTrustAnchorHealthCheck(metadataResolverRepository);

        trustAnchorEntityIds = new ArrayList<>();
        when(metadataResolverRepository.getTrustAnchorsEntityIds()).thenReturn(trustAnchorEntityIds);
    }

    @Test
    public void shouldReturnUnhealthyWhenNoTrustAnchorsAreFound() {
        Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isFalse();
    }

    @Test
    public void shouldReturnUnhealthyWhenAnyMetadataResolversDontContainMetadataMatchingTheEntityId() throws Exception {
        String entityId1 = "entityId1";
        String entityId2 = "entityId2";
        String entityId3 = "entityId3";
        List<String> entityIds = Arrays.asList(entityId1, entityId2, entityId3);
        trustAnchorEntityIds.addAll(entityIds);

        MetadataResolver validMetadataResolver = getValidMetadataResolver(entityId1);

        when(metadataResolverRepository.getEntityIdsWithResolver()).thenReturn(entityIds);
        when(metadataResolverRepository.getMetadataResolver(entityId1)).thenReturn(validMetadataResolver);
        when(metadataResolverRepository.getMetadataResolver(entityId2)).thenReturn(mock(MetadataResolver.class));
        when(metadataResolverRepository.getMetadataResolver(entityId3)).thenReturn(mock(MetadataResolver.class));

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
        List<String> entityIds = Arrays.asList(entityId1, entityId2, entityId3);
        trustAnchorEntityIds.addAll(entityIds);

        MetadataResolver validMetadataResolver = getValidMetadataResolver(entityId1);

        when(metadataResolverRepository.getEntityIdsWithResolver()).thenReturn(Collections.singletonList(entityId1));
        when(metadataResolverRepository.getMetadataResolver(entityId1)).thenReturn(validMetadataResolver);

        Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isFalse();
        assertThat(result.getMessage()).contains(entityId2, entityId3);
        assertThat(result.getMessage()).doesNotContain(entityId1);
    }

    @Test
    public void shouldReturnHealthyWhenAllMetadataResolversAreHealthy() throws Exception {
        String entityId1 = "entityId1";
        String entityId2 = "entityId2";
        List<String> entityIds = Arrays.asList(entityId1, entityId2);
        trustAnchorEntityIds.addAll(entityIds);

        MetadataResolver validMetadataResolver1 = getValidMetadataResolver(entityId1);
        MetadataResolver validMetadataResolver2 = getValidMetadataResolver(entityId2);

        when(metadataResolverRepository.getEntityIdsWithResolver()).thenReturn(entityIds);
        when(metadataResolverRepository.getMetadataResolver(entityId1)).thenReturn(validMetadataResolver1);
        when(metadataResolverRepository.getMetadataResolver(entityId2)).thenReturn(validMetadataResolver2);

        Result result = eidasTrustAnchorHealthCheck.check();

        assertThat(result.isHealthy()).isTrue();
    }

    private MetadataResolver getValidMetadataResolver(String entityId) throws MarshallingException, SignatureException, ResolverException {
        MetadataResolver metadataResolver = mock(MetadataResolver.class);
        when(metadataResolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityId)))).thenReturn(EntityDescriptorBuilder.anEntityDescriptor().build());

        return metadataResolver;
    }
}
