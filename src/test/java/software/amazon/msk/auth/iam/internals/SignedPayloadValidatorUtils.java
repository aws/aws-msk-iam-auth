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

import java.io.IOException;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import software.amazon.awssdk.http.auth.aws.signer.SignerConstant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class SignedPayloadValidatorUtils {
    private static final String VERSION = "version";
    private static final String HOST = "host";
    private static final String[] requiredKeys = {VERSION,
            HOST,
            SignerConstant.X_AMZ_CREDENTIAL.toLowerCase(),
            SignerConstant.X_AMZ_DATE.toLowerCase(),
            SignerConstant.X_AMZ_SIGNED_HEADERS.toLowerCase(),
            SignerConstant.X_AMZ_EXPIRES.toLowerCase(),
            SignerConstant.X_AMZ_SIGNATURE.toLowerCase(),
            SignerConstant.X_AMZ_ALGORITHM.toLowerCase()};

    private static final String ACTION = "action";
    private static final String[] optionalKeys = {
            "x-amz-security-token",
            ACTION,
    };
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("YYYYMMDD\'T\'HHMMSS\'Z\'");

    private SignedPayloadValidatorUtils() {
    }

    public static void validatePayload(byte[] payload, AuthenticationRequestParams params)
            throws IOException, ParseException {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> propertyMap = (Map<String, String>) mapper.readValue(payload, Map.class);

        assertEquals(10, propertyMap.size());

        //check if all required keys are present and non-empty
        List<String> missingRequiredKeys = Arrays.stream(requiredKeys)
                .filter(k -> propertyMap.get(k) == null || propertyMap.get(k).isEmpty())
                .collect(Collectors.toList());
        assertTrue(missingRequiredKeys.isEmpty());

        // check values for some keys
        assertEquals("2020_10_22", propertyMap.get(VERSION));
        assertEquals(params.getHost(), propertyMap.get(HOST));
        assertEquals("kafka-cluster:Connect", propertyMap.get(ACTION));
        assertEquals("host", propertyMap.get(SignerConstant.X_AMZ_SIGNED_HEADERS.toLowerCase()));
        assertEquals(SignerConstant.AWS4_SIGNING_ALGORITHM,
                propertyMap.get(SignerConstant.X_AMZ_ALGORITHM.toLowerCase()));
        assertTrue(dateFormat.parse(propertyMap.get(SignerConstant.X_AMZ_DATE.toLowerCase())).toInstant()
                .isBefore(Instant.now()));
        assertTrue(Integer.parseInt(propertyMap.get(SignerConstant.X_AMZ_EXPIRES.toLowerCase())) <= 900);
        String credential = propertyMap.get(SignerConstant.X_AMZ_CREDENTIAL.toLowerCase());
        assertNotNull(credential);
        String[] credentialArray = credential.split("/");
        assertEquals(5, credentialArray.length);
        assertEquals(params.getAwsCredentials().accessKeyId(), credentialArray[0]);
        String userAgent = propertyMap.get("user-agent");
        assertNotNull(userAgent);
        assertTrue(userAgent.startsWith("aws-msk-iam-auth"));

    }
}
