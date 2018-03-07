package uk.gov.ida.saml.core.domain;

import com.google.common.base.Optional;
import org.joda.time.DateTime;

public interface MdsAttributeValue {
    DateTime getFrom();

    Optional<DateTime> getTo();

    boolean isVerified();
}
