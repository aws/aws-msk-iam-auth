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

import software.amazon.awssdk.regions.Region;
import com.amazonaws.regions.Regions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AuthenticateRequestParamsTest {
    private static final String VALID_HOSTNAME = "b-3.unit-test.abcdef.kafka.us-west-2.amazonaws.com";
    private static final String HOSTNAME_NO_REGION = "abcd.efgh.com";
    private AwsCredentials credentials;
    private static final String ACCESS_KEY = "ACCESS_KEY";
    private static final String SECRET_KEY = "SECRET_KEY";
    private static final String USER_AGENT = "USER_AGENT";
    private static final Region TEST_EC2_REGION = Region.US_WEST_1;

    @BeforeEach
    public void setup() {
        credentials = AwsBasicCredentials.create(ACCESS_KEY, SECRET_KEY);
    }

    @Test
    public void testAllProperties() {
        AuthenticationRequestParams params = AuthenticationRequestParams
                .create(VALID_HOSTNAME, credentials, USER_AGENT);

        assertEquals("us-west-2", params.getRegion().id());
        assertEquals("kafka-cluster", params.getServiceScope());
        assertEquals(USER_AGENT, params.getUserAgent());
        assertEquals(VALID_HOSTNAME, params.getHost());
        assertEquals(ACCESS_KEY, params.getAwsCredentials().accessKeyId());
        assertEquals(SECRET_KEY, params.getAwsCredentials().secretAccessKey());
    }

    @Test
    public void testInvalidHost() {
        try (MockedStatic<Regions> regionsMockedStatic = Mockito.mockStatic(Regions.class)) {
            regionsMockedStatic.when(Regions::getCurrentRegion).thenReturn(null);
            assertThrows(IllegalArgumentException.class,
                    () -> AuthenticationRequestParams.create(HOSTNAME_NO_REGION, credentials, USER_AGENT));
        }
    }

    @Test
    public void testInvalidHostInEC2() {
        try (MockedStatic<Regions> regionsMockedStatic = Mockito.mockStatic(Regions.class)) {
            regionsMockedStatic.when(Regions::getCurrentRegion)
                .thenReturn(com.amazonaws.regions.Region.getRegion(Regions.US_WEST_1));
            AuthenticationRequestParams params = AuthenticationRequestParams.create(HOSTNAME_NO_REGION, credentials, USER_AGENT);
            assertEquals(Region.US_WEST_1, params.getRegion());
        }
    }

}
