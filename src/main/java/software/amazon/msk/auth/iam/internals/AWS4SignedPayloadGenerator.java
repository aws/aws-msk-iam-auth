/*
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
package software.amazon.msk.auth.iam.internals;

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.internal.SignerConstants;
import com.amazonaws.http.HttpMethodName;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;

/**
 * This class is used to generate the AWS Sigv4 signed authentication payload sent by the IAMSaslClient to the broker.
 * It configures a AWSSigner based on the authentication request parameters. It generates a request with the endpoint
 * set to the kafka broker (kafka:// as prefix), action set to kafka-cluster:Connect and the Http method as GET.
 * It then pre-signs the request using the credentials in the authentication request parameters and a expiration period
 * of 15 minutes. Afterwards, the signed request is converted into a key value map with headers and query parameters
 * acting as keys. Then the key value map is serialized as a JSON object and returned as bytes.
 */
class AWS4SignedPayloadGenerator implements SignedPayloadGenerator {
    private static final Logger log = LoggerFactory.getLogger(AWS4SignedPayloadGenerator.class);

    private static final String ACTION_KEY = "Action";
    private static final String ACTION_VALUE = "kafka-cluster:Connect";
    private static final String VERSION_KEY = "version";
    private static final String USER_AGENT_KEY = "user-agent";
    private static final int EXPIRY_DURATION_MINUTES = 15;

    @Override
    public byte[] signedPayload(@NonNull AuthenticationRequestParams params) throws PayloadGenerationException {
        final AWS4Signer signer = getConfiguredSigner(params);
        final DefaultRequest request = createRequestForSigning(params);

        signer.presignRequest(request, params.getAwsCredentials(), getExpiryDate());

        try {
            return toPayloadBytes(request, params);
        } catch (IOException e) {
            throw new PayloadGenerationException("Failure to create authentication payload ", e);
        }
    }

    private DefaultRequest createRequestForSigning(AuthenticationRequestParams params) {
        final DefaultRequest request = new DefaultRequest(params.getServiceScope());
        request.setHttpMethod(HttpMethodName.GET);
        try {
            request.setEndpoint(new URI("kafka://" + params.getHost()));
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Failed to parse host URI", e);
        }
        request.addParameter(ACTION_KEY, ACTION_VALUE);
        return request;
    }

    private java.util.Date getExpiryDate() {
        return Date.from(Instant.ofEpochMilli(Instant.now().toEpochMilli() + TimeUnit.MINUTES.toMillis(
                EXPIRY_DURATION_MINUTES)));
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

    private byte[] toPayloadBytes(DefaultRequest request, AuthenticationRequestParams params) throws IOException {
        final Map<String, String> keyValueMap = toKeyValueMap(request, params);

        final ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsBytes(keyValueMap);
    }

    /**
     * Convert the signed request into the map of key value strings that will be used to create the signed payload.
     * It adds all the query parameters and headers in the request object as entries in the map of key value strings.
     * It also adds the version of the AuthenticationRequestParams into the map of key value strings.
     *
     * @param request The signed request that contains the information to be converted into a key value map.
     * @param params  The authentication request parameters used to generate the signed request.
     * @return A key value map containing the query parameters and headers from the signed request.
     */
    private Map<String, String> toKeyValueMap(DefaultRequest request,
            AuthenticationRequestParams params) {
        final Map<String, String> keyValueMap = new HashMap<>();

        final Set<Map.Entry<String, List<String>>> parameterEntries = request.getParameters().entrySet();
        parameterEntries.stream().forEach(
                e -> keyValueMap.put(e.getKey().toLowerCase(), generateParameterValue(e.getKey(), e.getValue())));

        keyValueMap.put(VERSION_KEY, params.getVersion());
        keyValueMap.put(USER_AGENT_KEY, params.getUserAgent());

        //Add the headers.
        final Set<Map.Entry<String, String>> headerEntries = request.getHeaders().entrySet();
        headerEntries.stream().forEach(e -> keyValueMap.put(e.getKey().toLowerCase(), e.getValue()));

        return keyValueMap;
    }

    /**
     * Convert a query parameter value which is a list of strings into a single string.
     * The values of all query parameters other than signed headers are expected to be a list of length 1 or 0.
     * If the parameter value is of length 0, return an empty string.
     * If the parameter value is of length 1, return the sole element.
     * if the parameter value is longer than 1, join the list of string into a single string, separate by ";".
     *
     * @param key   The name of the query parameter.
     * @param value The list of strings that is the value of the query parameter.
     * @return A single joined string.
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
            final StringJoiner joiner = new StringJoiner(";");
            value.stream().forEach(joiner::add);
            return joiner.toString();
        }
        return value.get(0);
    }
}
