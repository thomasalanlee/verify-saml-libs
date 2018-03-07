package uk.gov.ida.saml.core.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Optional;
import org.joda.time.DateTime;

import java.io.Serializable;
import java.util.List;

public class Address implements MdsAttributeValue, Serializable {
    private boolean verified;
    private DateTime from;
    private Optional<DateTime> to = Optional.absent();
    private Optional<String> postCode = Optional.absent();
    private List<String> lines;
    private Optional<String> internationalPostCode = Optional.absent();
    private Optional<String> uprn = Optional.absent();

    public Address(
            List<String> lines,
            String postCode,
            String internationalPostCode,
            String uprn,
            DateTime from,
            DateTime to,
            boolean verified) {

        this.internationalPostCode = Optional.fromNullable(internationalPostCode);
        this.uprn = Optional.fromNullable(uprn);
        this.from = from;
        this.postCode = Optional.fromNullable(postCode);
        this.lines = lines;
        this.to = Optional.fromNullable(to);
        this.verified = verified;
    }

    @JsonCreator
    public Address(
            @JsonProperty("lines") List<String> lines,
            @JsonProperty("postCode") Optional<String> postCode,
            @JsonProperty("internationalPostCode") Optional<String> internationalPostCode,
            @JsonProperty("uprn") Optional<String> uprn,
            @JsonProperty("from") DateTime from,
            @JsonProperty("to") Optional<DateTime> to,
            @JsonProperty("verified") boolean verified) {
        this.lines = lines;
        this.postCode = postCode;
        this.internationalPostCode = internationalPostCode;
        this.uprn = uprn;
        this.from = from;
        this.to = to;
        this.verified = verified;
    }

    public List<String> getLines() {
        return lines;
    }

    public Optional<String> getPostCode() {
        return postCode;
    }

    public Optional<String> getInternationalPostCode() {
        return internationalPostCode;
    }

    public Optional<String> getUPRN() {
        return uprn;
    }

    public DateTime getFrom() {
        return from;
    }

    public Optional<DateTime> getTo() {
        return to;
    }

    public boolean isVerified() {
        return verified;
    }
}
