package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.internal.SignerConstants;
import com.amazonaws.http.HttpMethodName;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

public class AWS4SignedPayloadGenerator implements SignedPayloadGenerator {
    private static final Logger log = LoggerFactory.getLogger(AWS4SignedPayloadGenerator.class);

    private static final String ACTION_KEY = "Action";
    private static final String ACTION_VALUE = "kafka-cluster:Connect";
    private static final String VERSION_KEY = "version";

    @Override
    public byte [] signedPayload(AuthenticationRequestParams params) throws IOException {
        final AWS4Signer signer = getConfiguredSigner(params);
        final DefaultRequest request = new DefaultRequest(params.getServiceScope());
        request.setHttpMethod(HttpMethodName.GET);
        try {
            request.setEndpoint(new URI("kafka://" + params.getHost()));
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Failed to parse host URI", e);
        }
        request.addParameter(ACTION_KEY, ACTION_VALUE);
        //TODO: fill this in with a shorter value
        signer.presignRequest(request, params.getAwsCredentials(), null);
        return toPayloadBytes(request, params);
    }

    private AWS4Signer getConfiguredSigner(AuthenticationRequestParams params) {
        final AWS4Signer aws4Signer = new AWS4Signer();
        aws4Signer.setServiceName(params.getServiceScope());
        aws4Signer.setRegionName(params.getRegion().getName());
        if (log.isDebugEnabled()) {
            log.debug("Signer configured for {} service and {} region", aws4Signer.getServiceName(),
                    aws4Signer.getRegionName());
        }
        return aws4Signer;
    }

    private byte [] toPayloadBytes(DefaultRequest request, AuthenticationRequestParams params) throws IOException {
        Map<String, String> keyValueMap = toKeyValueMap(request, params);

        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsBytes(keyValueMap);
    }

    /**
     * Convert the signed request into the map of key value strings that will be used to create the signed payload.
     * It adds all the query parameters and headers in the request object as entries in the map of key value strings.
     * It also adds the version of the AuthenticationRequestParams into the map of key value strings.
     * @param request
     * @param params
     * @return
     */
    private Map<String, String> toKeyValueMap(DefaultRequest request,
            AuthenticationRequestParams params) {
        Map<String, String> keyValueMap = new HashMap<>();

        Set<Map.Entry<String, List<String>>> parameterEntries = request.getParameters().entrySet();
        parameterEntries.stream().forEach(
                e -> keyValueMap.put(e.getKey().toLowerCase(), generateParameterValue(e.getKey(), e.getValue())));

        keyValueMap.put(VERSION_KEY, params.getVersion());

        //Add the headers.
        Set<Map.Entry<String, String>> headerEntries = request.getHeaders().entrySet();
        headerEntries.stream().forEach(e -> keyValueMap.put(e.getKey().toLowerCase(), e.getValue()));

        return keyValueMap;
    }

    /**
     * Convert a query parameter value which is a list of strings into a single string.
     * The values of all query parameters other than signed headers are expected to be a list of length 1 or 0.
     * If the parameter value is of length 0, return an empty string.
     * If the parameter value is of length 1, return the sole element.
     * if the parameter value is longer than 1, join the list of string into a single string, separate by ";".
     * @param key
     * @param value
     * @return
     */
    private String generateParameterValue(String key, List<String> value) {
        if (value.isEmpty()) {
            return "";
        }
        if (value.size() > 1) {
            if (!SignerConstants.X_AMZ_SIGNED_HEADER.equals(key)) {
                throw new IllegalArgumentException(
                        "Unexpected number of arguments " + value.size() + " for query parameter " + key);
            }
            StringJoiner joiner = new StringJoiner(";");
            value.stream().forEach(joiner::add);
            return joiner.toString();
        }
        return value.get(0);
    }
}
