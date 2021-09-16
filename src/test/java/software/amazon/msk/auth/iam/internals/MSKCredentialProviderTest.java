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
import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.EC2ContainerCredentialsProviderWrapper;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.auth.WebIdentityTokenCredentialsProvider;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.profiles.ProfileFile;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static software.amazon.msk.auth.iam.internals.SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials;
import static software.amazon.msk.auth.iam.internals.SystemPropertyCredentialsUtils.runTestWithSystemPropertyProfile;

public class MSKCredentialProviderTest {
    private static final String ACCESS_KEY_VALUE = "ACCESS_KEY_VALUE";
    private static final String SECRET_KEY_VALUE = "SECRET_KEY_VALUE";
    private static final String ACCESS_KEY_VALUE_TWO = "ACCESS_KEY_VALUE_TWO";
    private static final String SECRET_KEY_VALUE_TWO = "SECRET_KEY_VALUE_TWO";
    private static final String TEST_PROFILE_NAME = "test_profile";
    private static final String PROFILE_ACCESS_KEY_VALUE = "PROFILE_ACCESS_KEY";
    private static final String PROFILE_SECRET_KEY_VALUE = "PROFILE_SECRET_KEY";
    private static final String TEST_ROLE_ARN = "TEST_ROLE_ARN";
    private static final String TEST_ROLE_SESSION_NAME = "TEST_ROLE_SESSION_NAME";
    private static final String SESSION_TOKEN = "SESSION_TOKEN";
    private static final String AWS_ROLE_ARN = "awsRoleArn";
    private static final String AWS_PROFILE_NAME = "awsProfileName";
    private static final String AWS_DEBUG_CREDS_NAME = "awsDebugCreds";

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
            assertFalse(provider.getShouldDebugCreds());

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
            optionsMap.put(AWS_PROFILE_NAME, "MISSING_PROFILE");
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

        runTestWithSystemPropertyProfile(() -> {
            ProfileFile profileFile = getProfileFile();
            MSKCredentialProvider provider = new MSKCredentialProvider(Collections.emptyMap()) {
                protected AWSCredentialsProviderChain getDefaultProvider() {
                    return new AWSCredentialsProviderChain(new EnvironmentVariableCredentialsProvider(),
                            new SystemPropertiesCredentialsProvider(),
                            WebIdentityTokenCredentialsProvider.create(),
                            new EnhancedProfileCredentialsProvider(profileFile, null),
                            new EC2ContainerCredentialsProviderWrapper());
                }
            };

            AWSCredentials credentials = provider.getCredentials();

            assertEquals(PROFILE_ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
            assertEquals(PROFILE_SECRET_KEY_VALUE, credentials.getAWSSecretKey());
        }, TEST_PROFILE_NAME);
    }

    @Test
    public void testProfileName() {
        ProfileFile profileFile = getProfileFile();
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_PROFILE_NAME, "test_profile");
        MSKCredentialProvider.ProviderBuilder providerBuilder = new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            EnhancedProfileCredentialsProvider createEnhancedProfileCredentialsProvider(String profileName) {
                assertEquals(TEST_PROFILE_NAME, profileName);
                return new EnhancedProfileCredentialsProvider(profileFile, TEST_PROFILE_NAME);
            }
        };
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        assertEquals(PROFILE_ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
        assertEquals(PROFILE_SECRET_KEY_VALUE, credentials.getAWSSecretKey());
    }

    @Test
    public void testAwsRoleArn() {
        STSAssumeRoleSessionCredentialsProvider mockStsRoleProvider = Mockito
                .mock(STSAssumeRoleSessionCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.getCredentials())
                .thenReturn(new BasicSessionCredentials(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);

        MSKCredentialProvider.ProviderBuilder providerBuilder = new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                                    String sessionName, String stsRegion) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals("aws-msk-iam-auth", sessionName);
                return mockStsRoleProvider;
            }
        };
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        assertTrue(credentials instanceof BasicSessionCredentials);
        BasicSessionCredentials sessionCredentials = (BasicSessionCredentials) credentials;
        assertEquals(ACCESS_KEY_VALUE, sessionCredentials.getAWSAccessKeyId());
        assertEquals(SECRET_KEY_VALUE, sessionCredentials.getAWSSecretKey());
        assertEquals(SESSION_TOKEN, sessionCredentials.getSessionToken());

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnWithDebugCreds() {
        STSAssumeRoleSessionCredentialsProvider mockStsRoleProvider = Mockito
                .mock(STSAssumeRoleSessionCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.getCredentials())
                .thenReturn(new BasicSessionCredentials(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put(AWS_DEBUG_CREDS_NAME, "true");

        MSKCredentialProvider.ProviderBuilder providerBuilder = new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                    String sessionName, String stsRegion) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals("aws-msk-iam-auth", sessionName);
                return mockStsRoleProvider;
            }
        };

        AWSSecurityTokenService mockSts = Mockito.mock(AWSSecurityTokenService.class);
        Mockito.when(mockSts.getCallerIdentity(Mockito.any(GetCallerIdentityRequest.class))).thenReturn(new GetCallerIdentityResult().withUserId("TEST_USER_ID").withAccount("TEST_ACCOUNT").withArn("TEST_ARN"));
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder) {
            AWSSecurityTokenService getStsClientForDebuggingCreds(AWSCredentials credentials) {
                return mockSts;
            }
        };

        assertTrue(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        assertTrue(credentials instanceof BasicSessionCredentials);
        BasicSessionCredentials sessionCredentials = (BasicSessionCredentials) credentials;
        assertEquals(ACCESS_KEY_VALUE, sessionCredentials.getAWSAccessKeyId());
        assertEquals(SECRET_KEY_VALUE, sessionCredentials.getAWSSecretKey());
        assertEquals(SESSION_TOKEN, sessionCredentials.getSessionToken());

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
        Mockito.verify(mockSts, times(1)).getCallerIdentity(any(GetCallerIdentityRequest.class));
    }

    @Test
    public void testAwsRoleArnAndSessionName() {
        STSAssumeRoleSessionCredentialsProvider mockStsRoleProvider = Mockito
                .mock(STSAssumeRoleSessionCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.getCredentials())
                .thenReturn(new BasicSessionCredentials(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);

        MSKCredentialProvider.ProviderBuilder providerBuilder = new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                                    String sessionName, String stsRegion) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(TEST_ROLE_SESSION_NAME, sessionName);
                return mockStsRoleProvider;
            }
        };
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        assertTrue(credentials instanceof BasicSessionCredentials);
        BasicSessionCredentials sessionCredentials = (BasicSessionCredentials) credentials;
        assertEquals(ACCESS_KEY_VALUE, sessionCredentials.getAWSAccessKeyId());
        assertEquals(SECRET_KEY_VALUE, sessionCredentials.getAWSSecretKey());
        assertEquals(SESSION_TOKEN, sessionCredentials.getSessionToken());

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnSessionNameAndStsRegion() {
        STSAssumeRoleSessionCredentialsProvider mockStsRoleProvider = Mockito
                .mock(STSAssumeRoleSessionCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.getCredentials())
                .thenReturn(new BasicSessionCredentials(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);
        optionsMap.put("awsStsRegion", "eu-west-1");

        MSKCredentialProvider.ProviderBuilder providerBuilder = new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                                    String sessionName, String stsRegion) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(TEST_ROLE_SESSION_NAME, sessionName);
                assertEquals("eu-west-1", stsRegion);
                return mockStsRoleProvider;
            }
        };
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        assertTrue(credentials instanceof BasicSessionCredentials);
        BasicSessionCredentials sessionCredentials = (BasicSessionCredentials) credentials;
        assertEquals(ACCESS_KEY_VALUE, sessionCredentials.getAWSAccessKeyId());
        assertEquals(SECRET_KEY_VALUE, sessionCredentials.getAWSSecretKey());
        assertEquals(SESSION_TOKEN, sessionCredentials.getSessionToken());

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testProfileNameAndRoleArn() {
        ProfileFile profileFile = getProfileFile();
        STSAssumeRoleSessionCredentialsProvider mockStsRoleProvider = Mockito
                .mock(STSAssumeRoleSessionCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.getCredentials())
                .thenReturn(new BasicSessionCredentials(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_PROFILE_NAME, "test_profile");
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        MSKCredentialProvider.ProviderBuilder providerBuilder = new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            EnhancedProfileCredentialsProvider createEnhancedProfileCredentialsProvider(String profileName) {
                assertEquals(TEST_PROFILE_NAME, profileName);
                return new EnhancedProfileCredentialsProvider(profileFile, TEST_PROFILE_NAME);
            }
            STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                                    String sessionName, String stsRegion) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals("aws-msk-iam-auth", sessionName);
                return mockStsRoleProvider;
            }
        };
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        provider.close();

        assertEquals(PROFILE_ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
        assertEquals(PROFILE_SECRET_KEY_VALUE, credentials.getAWSSecretKey());
        Mockito.verify(mockStsRoleProvider, times(0)).getCredentials();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    private ProfileFile getProfileFile() {
        return ProfileFile.builder().content(new File(getProfileResourceURL().getFile()).toPath()).type(
                ProfileFile.Type.CREDENTIALS).build();
    }

    private URL getProfileResourceURL() {
        return getClass().getClassLoader().getResource("profile_config_file");
    }

}
