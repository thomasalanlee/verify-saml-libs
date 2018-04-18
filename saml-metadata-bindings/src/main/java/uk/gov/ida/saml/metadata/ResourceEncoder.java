package uk.gov.ida.saml.metadata;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class ResourceEncoder {
    public static String entityIdAsResource(String entityId) throws UnsupportedEncodingException {
        //FIXME Double encoding to account for S3 object key being already encoded before made into a REST resource (i.e. once on submission and once as endpoint)
        return URLEncoder.encode(URLEncoder.encode(entityId, StandardCharsets.UTF_8.name()), StandardCharsets.UTF_8.name());
    }
}
