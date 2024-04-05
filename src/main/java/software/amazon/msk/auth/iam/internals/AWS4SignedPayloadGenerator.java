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

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.temporal.ChronoUnit;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4PresignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.auth.aws.internal.signer.util.SignerConstant;

/**
 * This class is used to generate the AWS Sigv4 signed authentication payload sent by the IAMSaslClient to the broker.
 * It configures a AWSSigner based on the authentication request parameters. It generates a request with the endpoint
 * set to the kafka broker (kafka:// as prefix), action set to kafka-cluster:Connect and the Http method as GET.
 * It then pre-signs the request using the credentials in the authentication request parameters and a expiration period
 * of 15 minutes. Afterwards, the signed request is converted into a key value map with headers and query parameters
 * acting as keys. Then the key value map is serialized as a JSON object and returned as bytes.
 */
public class AWS4SignedPayloadGenerator implements SignedPayloadGenerator {
    private static final Logger log = LoggerFactory.getLogger(AWS4SignedPayloadGenerator.class);

    private static final String ACTION_KEY = "Action";
    private static final String ACTION_VALUE = "kafka-cluster:Connect";
    private static final String VERSION_KEY = "version";
    private static final String USER_AGENT_KEY = "user-agent";
    private static final String PROTOCOL = "https";
    private static final int EXPIRY_DURATION_MINUTES = 15;

    @Override
    public byte[] signedPayload(@NonNull AuthenticationRequestParams params) throws PayloadGenerationException {
        final SdkHttpFullRequest request = presignRequest(params);

        try {
            return toPayloadBytes(request, params);
        } catch (IOException e) {
            throw new PayloadGenerationException("Failure to create authentication payload ", e);
        }
    }

    /**
     * Presigns the request with AWS sigv4
     *
     * @param params authentication request parameters
     * @return presigned request
     */
    public SdkHttpFullRequest presignRequest(@NonNull AuthenticationRequestParams params) {
        SdkHttpFullRequest request = createRequestForSigning(params);
        Aws4PresignerParams signingParams = createSigningParams(params);

        return Aws4Signer.create().presign(request, signingParams);
    }

    private SdkHttpFullRequest createRequestForSigning(AuthenticationRequestParams params) {
        return SdkHttpFullRequest.builder()
            .method(SdkHttpMethod.GET)
            .protocol(PROTOCOL)
            .host(params.getHost())
            .appendRawQueryParameter(ACTION_KEY, ACTION_VALUE)
            .build();
    }

    private Aws4PresignerParams createSigningParams(AuthenticationRequestParams params) {
        return Aws4PresignerParams.builder()
            .awsCredentials(params.getAwsCredentials())
            .expirationTime(getExpiry())
            .signingRegion(params.getRegion())
            .signingName(params.getServiceScope())
            .build();
    }

    private Instant getExpiry() {
        return Instant.now().plus(EXPIRY_DURATION_MINUTES, ChronoUnit.MINUTES);
    }

    private byte[] toPayloadBytes(SdkHttpFullRequest request, AuthenticationRequestParams params) throws IOException {
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
    private Map<String, String> toKeyValueMap(SdkHttpFullRequest request,
            AuthenticationRequestParams params) {
        final Map<String, String> keyValueMap = new HashMap<>();

        final Set<Map.Entry<String, List<String>>> parameterEntries = request.rawQueryParameters().entrySet();
        parameterEntries.stream().forEach(
                e -> keyValueMap.put(e.getKey().toLowerCase(), generateParameterValue(e.getKey(), e.getValue())));

        keyValueMap.put(VERSION_KEY, params.getVersion());
        keyValueMap.put(USER_AGENT_KEY, params.getUserAgent());

        //Add the headers.
        final Set<Map.Entry<String, List<String>>> headerEntries = request.headers().entrySet();
        headerEntries.stream()
            .forEach(e -> keyValueMap.put(e.getKey().toLowerCase(), e.getValue().get(0)));

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
            if (!SignerConstant.X_AMZ_SIGNED_HEADERS.equals(key)) {
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
