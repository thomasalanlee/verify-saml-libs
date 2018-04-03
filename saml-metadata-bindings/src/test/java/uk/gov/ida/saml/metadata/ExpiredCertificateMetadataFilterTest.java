package uk.gov.ida.saml.metadata;


import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;

import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

public class ExpiredCertificateMetadataFilterTest {

    private MetadataFactory metadataFactory = new MetadataFactory();
    private MetadataFilter metadataFilter;
    private BasicParserPool parserPool = new BasicParserPool();

    @Before
    public void setUp() throws Exception {
        metadataFilter = new ExpiredCertificateMetadataFilter();
        parserPool.initialize();
    }

    @Test
    public void shouldFailToFilterLoadingValidMetadataWhenSignedWithExpiredCertificate() throws Exception {
        try {
            DateTimeUtils.setCurrentMillisFixed(DateTime.now().plusYears(1000).getMillis());
            InputStream inputStream = IOUtils.toInputStream(metadataFactory.signedMetadata(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY));
            XMLObject metadata = XMLObjectSupport.unmarshallFromInputStream(parserPool, inputStream);
            metadataFilter.filter(metadata);
            fail("Expected exception not thrown");
        } catch (FilterException e){
            assertThat(true).isTrue();
        } finally {
            DateTimeUtils.setCurrentMillisSystem();
        }
    }

    @Test
    public void shouldFailToFilterLoadingValidMetadataWhenSignedWithNotYetValidCertificate() throws Exception {
        try {
            DateTimeUtils.setCurrentMillisFixed(DateTime.now().minusYears(1000).getMillis());
            InputStream inputStream = IOUtils.toInputStream(metadataFactory.signedMetadata(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY));
            XMLObject metadata = XMLObjectSupport.unmarshallFromInputStream(parserPool, inputStream);
            metadataFilter.filter(metadata);
            fail("Expected exception not thrown");
        } catch (FilterException e){
            assertThat(true).isTrue();
        } finally {
            DateTimeUtils.setCurrentMillisSystem();
        }
    }

    @Test
    public void shouldFilterMetadataSuccessfully() throws Exception {
        InputStream inputStream = IOUtils.toInputStream(metadataFactory.signedMetadata(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, TestCertificateStrings.METADATA_SIGNING_A_PRIVATE_KEY));
        XMLObject metadata = XMLObjectSupport.unmarshallFromInputStream(parserPool, inputStream);
        metadata = metadataFilter.filter(metadata);
        Assert.assertNotNull("metadata should not have been filtered out", metadata);
    }
}
