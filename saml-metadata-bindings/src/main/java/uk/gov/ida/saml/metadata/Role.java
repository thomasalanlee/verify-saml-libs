package uk.gov.ida.saml.metadata;

import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;

import javax.xml.namespace.QName;

public enum Role {
    SP(SPSSODescriptor.DEFAULT_ELEMENT_NAME),
    IDP(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

    private final QName roleDescriptor;

    Role(final QName roleDescriptor) {
        this.roleDescriptor = roleDescriptor;
    }

    public QName getRoleDescriptor() {
        return roleDescriptor;
    }
}
