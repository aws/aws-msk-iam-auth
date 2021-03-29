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
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.auth.profile.ProfilesConfigFile;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static software.amazon.msk.auth.iam.internals.SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials;
import static software.amazon.msk.auth.iam.internals.SystemPropertyCredentialsUtils.runTestWithSystemPropertyProfile;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MSKCredentialProviderTest {
    private static final String ACCESS_KEY_VALUE = "ACCESS_KEY_VALUE";
    private static final String SECRET_KEY_VALUE = "SECRET_KEY_VALUE";
    private static final String ACCESS_KEY_VALUE_TWO = "ACCESS_KEY_VALUE_TWO";
    private static final String SECRET_KEY_VALUE_TWO = "SECRET_KEY_VALUE_TWO";
    public static final String TEST_PROFILE_NAME = "test_profile";
    public static final String PROFILE_ACCESS_KEY_VALUE = "PROFILE_ACCESS_KEY";
    public static final String PROFILE_SECRET_KEY_VALUE = "PROFILE_SECRET_KEY";

    /**
     * If no options are passed in it should use the default credentials provider
     * which should pick up the java system properties.
     */
    @Test
    public void testNoOptions() {
        runDefaultTest();
    }

    private void runDefaultTest() {
        runTestWithSystemPropertyCredentials(() -> {
            MSKCredentialProvider provider = new MSKCredentialProvider(Collections.emptyMap());

            AWSCredentials credentials = provider.getCredentials();

            assertEquals(ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
            assertEquals(SECRET_KEY_VALUE, credentials.getAWSSecretKey());
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
    }

    /**
     * If a profile name is passed in but there is no profile by that name
     * it should still use the default credential provider.
     */
    @Test
    public void testMissingProfileName() {
        runTestWithSystemPropertyCredentials(() -> {
            Map<String, String> optionsMap = new HashMap<>();
            optionsMap.put("awsProfileName", "MISSING_PROFILE");
            MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap);

            AWSCredentials credentials = provider.getCredentials();

            assertEquals(ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
            assertEquals(SECRET_KEY_VALUE, credentials.getAWSSecretKey());
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
    }

    /**
     * If the credentials available to the default credential provider change,
     * the new credentials should be picked up.
     *
     * @throws IOException
     */
    @Test
    public void testChangingCredentials() throws IOException {
        runDefaultTest();

        //Set up a temp directory with the aws profile
        Path tempDir = Files.createTempDirectory("test_aws_home");
        Path awsDir = Files.createDirectory(tempDir.resolve(".aws"));
        Path tempCredsFile = awsDir.resolve("credentials");
        Files.copy(Paths.get(getProfileResourceURL().getPath()), tempCredsFile);

        tempCredsFile.toFile().deleteOnExit();
        awsDir.toFile().deleteOnExit();
        tempDir.toFile().deleteOnExit();

        try {

            runTestWithSystemPropertyProfile(() -> {
                MSKCredentialProvider provider = new MSKCredentialProvider(Collections.emptyMap());

                AWSCredentials credentials = provider.getCredentials();

                assertEquals(PROFILE_ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
                assertEquals(PROFILE_SECRET_KEY_VALUE, credentials.getAWSSecretKey());
            }, TEST_PROFILE_NAME, tempDir.toString());
        } finally {
            Files.deleteIfExists(tempCredsFile);
            Files.deleteIfExists(awsDir);
            Files.deleteIfExists(tempDir);
        }
    }

    @Test
    public void testProfileName() {
        ProfilesConfigFile profilesConfig = getProfilesConfigFile();
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsProfileName", "test_profile");
        MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap,
                 Optional.of(new ProfileCredentialsProvider(profilesConfig, TEST_PROFILE_NAME)));

        AWSCredentials credentials = provider.getCredentials();
        assertEquals(PROFILE_ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
        assertEquals(PROFILE_SECRET_KEY_VALUE, credentials.getAWSSecretKey());
    }

    private ProfilesConfigFile getProfilesConfigFile() {
        File file = new File(getProfileResourceURL().getFile());
        return new ProfilesConfigFile(file);
    }

    private URL getProfileResourceURL() {
        return getClass().getClassLoader().getResource("profile_config_file");
    }

}
