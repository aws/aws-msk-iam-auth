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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.amazonaws.auth.*;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.amazonaws.SdkBaseException;
import com.amazonaws.SdkClientException;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
                protected AwsCredentialsProvider getDefaultProvider() {
                    return DefaultCredentialsProvider.builder().profileFile(profileFile).build();
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
            ProfileCredentialsProvider createProfileCredentialsProvider(String profileName) {
                assertEquals(TEST_PROFILE_NAME, profileName);
                return ProfileCredentialsProvider.builder().profileFile(profileFile).profileName(TEST_PROFILE_NAME).build();
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
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveCredentials())
                .thenReturn(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);

        MSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnWithDebugCreds() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveCredentials())
                .thenReturn(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put(AWS_DEBUG_CREDS_NAME, "true");

        MSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");

        StsClient mockSts = Mockito.mock(StsClient.class);
        Mockito.when(mockSts.getCallerIdentity()).thenReturn(GetCallerIdentityResponse.builder().userId("TEST_USER_ID").account("TEST_ACCOUNT").arn("TEST_ARN").build());
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder) {
            StsClient getStsClientForDebuggingCreds(AwsCredentials credentials) {
                return mockSts;
            }
        };

        assertTrue(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
        Mockito.verify(mockSts, times(1)).getCallerIdentity();
    }

    @Test
    public void testEc2CredsWithDebuCredsNoAccessToSts_Succeed() {
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_DEBUG_CREDS_NAME, "true");


        AwsCredentialsProvider mockEc2CredsProvider = Mockito.mock(AwsCredentialsProvider.class);
        Mockito.when(mockEc2CredsProvider.resolveCredentials())
                .thenReturn(AwsBasicCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO));

        StsClient mockSts = Mockito.mock(StsClient.class);
        Mockito.when(mockSts.getCallerIdentity())
                .thenThrow(new SdkClientException("TEST TEST"));

        MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return AwsCredentialsProviderChain.of(mockEc2CredsProvider);
            }

            StsClient getStsClientForDebuggingCreds(AwsCredentials credentials) {
                return mockSts;
            }
        };
        assertTrue(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();

        validateBasicCredentialsTwo(credentials);

        provider.close();
        Mockito.verify(mockSts, times(1)).getCallerIdentity();
        Mockito.verify(mockEc2CredsProvider, times(1)).resolveCredentials();
        Mockito.verifyNoMoreInteractions(mockEc2CredsProvider);
    }


    @Test
    public void testAwsRoleArnAndSessionName() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveCredentials())
                .thenReturn(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);

        MSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                TEST_ROLE_SESSION_NAME);
        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnSessionNameAndStsRegion() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveCredentials())
                .thenReturn(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);
        optionsMap.put("awsStsRegion", "eu-west-1");

        MSKCredentialProvider.ProviderBuilder providerBuilder = new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
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
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testProfileNameAndRoleArn() {
        ProfileFile profileFile = getProfileFile();
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveCredentials())
                .thenReturn(AwsSessionCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO, SESSION_TOKEN));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_PROFILE_NAME, "test_profile");
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        MSKCredentialProvider.ProviderBuilder providerBuilder = new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            ProfileCredentialsProvider createProfileCredentialsProvider(String profileName) {
                assertEquals(TEST_PROFILE_NAME, profileName);
                return getProfileCredentialsProvider(profileName, profileFile);
            }
            StsAssumeRoleCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
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
        Mockito.verify(mockStsRoleProvider, times(0)).resolveCredentials();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    private static ProfileCredentialsProvider getProfileCredentialsProvider(String profileName, ProfileFile profileFile) {
        return ProfileCredentialsProvider.builder().profileName(profileName).profileFile(profileFile).build();
    }

    @Test
    public void testRoleCredsWithTwoRetriableErrors() {
        testRoleCredsWithRetriableErrors(2);
    }

    @Test
    public void testRoleCredsWithThreeRetriableErrors() {
        testRoleCredsWithRetriableErrors(3);
    }

    @Test
    public void testRoleCredsWithFourRetriableErrors_ThrowsException() {
        int numExceptions = 4;
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = setupMockStsRoleCredentialsProviderWithRetriableExceptions(numExceptions);

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);

        MSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");

        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return AwsCredentialsProviderChain.of(software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider.create());
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        assertThrows(SdkClientException.class, () -> provider.getCredentials());

        Mockito.verify(mockStsRoleProvider, times(numExceptions)).resolveCredentials();
        Mockito.verifyNoMoreInteractions(mockStsRoleProvider);
    }

    @Test
    public void testEc2CredsWithTwoRetriableErrorsCustomRetry() {
        testEc2CredsWithRetriableErrorsCustomRetry(2);
    }

    @Test
    public void testEc2CredsWithFiveRetriableErrorsCustomRetry() {
        testEc2CredsWithRetriableErrorsCustomRetry(5);
    }

    @Test
    public void testEc2CredsWithSixRetriableErrorsCustomRetry_ThrowsException() {
        int numExceptions = 6;
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsMaxRetries", "5");

        AwsCredentialsProvider mockEc2CredsProvider = setupMockDefaultProviderWithRetriableExceptions(numExceptions);

        MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return AwsCredentialsProviderChain.of(mockEc2CredsProvider);
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        assertThrows(SdkClientException.class, () -> provider.getCredentials());

        Mockito.verify(mockEc2CredsProvider, times(numExceptions)).resolveCredentials();
        Mockito.verifyNoMoreInteractions(mockEc2CredsProvider);
    }

    @Test
    public void testEc2CredsWithOnrRetriableErrorsCustomZeroRetry_ThrowsException() {
        int numExceptions = 1;
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsMaxRetries", "0");

        AwsCredentialsProvider mockEc2CredsProvider = setupMockDefaultProviderWithRetriableExceptions(numExceptions);

        MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return AwsCredentialsProviderChain.of(mockEc2CredsProvider);
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        assertThrows(SdkClientException.class, () -> provider.getCredentials());

        Mockito.verify(mockEc2CredsProvider, times(numExceptions)).resolveCredentials();
        Mockito.verifyNoMoreInteractions(mockEc2CredsProvider);
    }




    private void testEc2CredsWithRetriableErrorsCustomRetry(int numExceptions) {
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsMaxRetries", "5");

        AwsCredentialsProvider mockEc2CredsProvider = setupMockDefaultProviderWithRetriableExceptions(numExceptions);

        MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return AwsCredentialsProviderChain.of(mockEc2CredsProvider);
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();

        validateBasicCredentialsTwo(credentials);

        provider.close();
        Mockito.verify(mockEc2CredsProvider, times(numExceptions + 1)).resolveCredentials();
        Mockito.verifyNoMoreInteractions(mockEc2CredsProvider);
    }

    private void testRoleCredsWithRetriableErrors(int numExceptions) {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = setupMockStsRoleCredentialsProviderWithRetriableExceptions(
                numExceptions);

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);

        MSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");

        MSKCredentialProvider provider = new MSKCredentialProvider(providerBuilder) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return AwsCredentialsProviderChain.of(EnvironmentVariableCredentialsProvider.create());
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        AWSCredentials credentials = provider.getCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(numExceptions + 1)).resolveCredentials();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
        Mockito.verifyNoMoreInteractions(mockStsRoleProvider);
    }

    private MSKCredentialProvider.ProviderBuilder getProviderBuilder(StsAssumeRoleCredentialsProvider mockStsRoleProvider,
            Map<String, String> optionsMap, String s) {
        return new MSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                    String sessionName, String stsRegion) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(s, sessionName);
                return mockStsRoleProvider;
            }
        };
    }

    private void validateBasicSessionCredentials(AWSCredentials credentials) {
        assertTrue(credentials instanceof BasicSessionCredentials);
        BasicSessionCredentials sessionCredentials = (BasicSessionCredentials) credentials;
        assertEquals(ACCESS_KEY_VALUE, sessionCredentials.getAWSAccessKeyId());
        assertEquals(SECRET_KEY_VALUE, sessionCredentials.getAWSSecretKey());
        assertEquals(SESSION_TOKEN, sessionCredentials.getSessionToken());
    }

    private void validateBasicCredentialsTwo(AWSCredentials credentials) {
        assertTrue(credentials instanceof BasicAWSCredentials);
        assertEquals(ACCESS_KEY_VALUE_TWO, credentials.getAWSAccessKeyId());
        assertEquals(SECRET_KEY_VALUE_TWO, credentials.getAWSSecretKey());
    }


    private StsAssumeRoleCredentialsProvider setupMockStsRoleCredentialsProviderWithRetriableExceptions(int numErrors) {
        SdkBaseException[] exceptionsToThrow = getSdkBaseExceptions(numErrors);

        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveCredentials())
                .thenThrow(exceptionsToThrow)
                .thenReturn(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN));
        return mockStsRoleProvider;
    }

    private SdkBaseException[] getSdkBaseExceptions(int numErrors) {
        final SdkBaseException exceptionFromProvider = new SdkClientException("TEST TEST TEST");
        return IntStream.range(0, numErrors).mapToObj(i -> exceptionFromProvider)
                .collect(Collectors.toList()).toArray(new SdkBaseException[numErrors]);
    }

    private AwsCredentialsProvider setupMockDefaultProviderWithRetriableExceptions(int numErrors) {
        SdkBaseException[] exceptionsToThrow = getSdkBaseExceptions(numErrors);
        AwsCredentialsProvider mockEc2Provider = Mockito.mock(AwsCredentialsProvider.class);

        Mockito.when(mockEc2Provider.resolveCredentials())
                .thenThrow(exceptionsToThrow)
                .thenReturn(AwsBasicCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO));
        return mockEc2Provider;
    }


    private ProfileFile getProfileFile() {
        return ProfileFile.builder().content(new File(getProfileResourceURL().getFile()).toPath()).type(
                ProfileFile.Type.CREDENTIALS).build();
    }

    private URL getProfileResourceURL() {
        return getClass().getClassLoader().getResource("profile_config_file");
    }

}
