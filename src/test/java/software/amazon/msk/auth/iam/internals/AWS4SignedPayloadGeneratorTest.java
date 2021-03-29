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

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.text.ParseException;

public class AWS4SignedPayloadGeneratorTest {
    private static final String VALID_HOSTNAME = "b-3.unit-test.abcdef.kafka.us-west-2.amazonaws.com";
    private static final String ACCESS_KEY = "ACCESS_KEY";
    private static final String SECRET_KEY = "SECRET_KEY";
    private static final String USER_AGENT = "USER_AGENT";

    private AWSCredentials credentials;

    @BeforeEach
    public void setup() {
        credentials = new BasicAWSCredentials(ACCESS_KEY, SECRET_KEY);
    }

    @Test
    public void testSigning() throws IOException, ParseException {
        AuthenticationRequestParams params = AuthenticationRequestParams
                .create(VALID_HOSTNAME, credentials, UserAgentUtils.getUserAgentValue());
        AWS4SignedPayloadGenerator generator = new AWS4SignedPayloadGenerator();
        byte[] signedPayload = generator.signedPayload(params);

        assertNotNull(signedPayload);
        SignedPayloadValidatorUtils.validatePayload(signedPayload, params);
    }
}
