package uk.gov.ida.saml.core.test.builders.metadata;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml.saml2.metadata.OrganizationName;
import org.opensaml.saml.saml2.metadata.OrganizationURL;
import org.opensaml.saml.saml2.metadata.impl.OrganizationNameBuilder;
import org.opensaml.saml.saml2.metadata.impl.OrganizationURLBuilder;
import uk.gov.ida.saml.core.IdaConstants;

import java.util.Optional;

public class OrganizationBuilder {

    private Optional<OrganizationDisplayName> organizationDisplayName = Optional.ofNullable(OrganizationDisplayNameBuilder.anOrganizationDisplayName().build());
    private Optional<OrganizationName> name = Optional.ofNullable(createName("org-name"));

    private Optional<OrganizationURL> url = Optional.ofNullable(createUrl("http://org"));

    public static OrganizationBuilder anOrganization() {
        return new OrganizationBuilder();
    }

    public Organization build() {
        Organization organization = new org.opensaml.saml.saml2.metadata.impl.OrganizationBuilder().buildObject();

        if (organizationDisplayName.isPresent()) {
            organization.getDisplayNames().add(organizationDisplayName.get());
        }
        if (name.isPresent()){
            organization.getOrganizationNames().add(name.get());
        }
        if (url.isPresent()){
            organization.getURLs().add(url.get());
        }

        return organization;
    }

    private OrganizationName createName(String name) {
        OrganizationName organizationName = new OrganizationNameBuilder().buildObject();
        organizationName.setValue(name);
        organizationName.setXMLLang(IdaConstants.IDA_LANGUAGE);
        return organizationName;

    }

    private OrganizationURL createUrl(String url) { 
        OrganizationURL buildObject = new OrganizationURLBuilder().buildObject();
        buildObject.setValue(url);
        buildObject.setXMLLang(IdaConstants.IDA_LANGUAGE);
        return buildObject;
    }

    public OrganizationBuilder withDisplayName(OrganizationDisplayName organizationDisplayName) {
        this.organizationDisplayName = Optional.ofNullable(organizationDisplayName);
        return this;
    }

    public OrganizationBuilder withName(String name) {
        this.name = Optional.ofNullable(createName(name));
        return this;
    }

    public OrganizationBuilder withUrl(String url) {
        this.url = Optional.ofNullable(createUrl(url));
        return this;
    }
}
