package uk.gov.ida.saml.core.test.builders.metadata;

import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import uk.gov.ida.saml.core.IdaConstants;

public class OrganizationDisplayNameBuilder {

    private String organizationName = "org-display-name";

    public static OrganizationDisplayNameBuilder anOrganizationDisplayName() {
        return new OrganizationDisplayNameBuilder();
    }

    public OrganizationDisplayName build() {
        OrganizationDisplayName organizationDisplayName = new org.opensaml.saml.saml2.metadata.impl.OrganizationDisplayNameBuilder()
                .buildObject();
        organizationDisplayName.setValue(organizationName);
        organizationDisplayName.setXMLLang(IdaConstants.IDA_LANGUAGE);
        return organizationDisplayName;
    }

    public OrganizationDisplayNameBuilder withName(String organizationName) {
        this.organizationName = organizationName;
        return this;
    }
}
