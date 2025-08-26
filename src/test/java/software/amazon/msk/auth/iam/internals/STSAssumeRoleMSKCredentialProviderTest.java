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

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.times;
import static software.amazon.msk.auth.iam.internals.SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials;
import static software.amazon.msk.auth.iam.internals.SystemPropertyCredentialsUtils.runTestWithSystemPropertyProfile;

public class STSAssumeRoleMSKCredentialProviderTest {
    private static final String ACCESS_KEY_VALUE = "ACCESS_KEY_VALUE";
    private static final String SECRET_KEY_VALUE = "SECRET_KEY_VALUE";
    private static final String ACCESS_KEY_VALUE_TWO = "ACCESS_KEY_VALUE_TWO";
    private static final String SECRET_KEY_VALUE_TWO = "SECRET_KEY_VALUE_TWO";
    private static final String TEST_PROFILE_NAME = "test_profile";
    private static final String PROFILE_ACCESS_KEY_VALUE = "PROFILE_ACCESS_KEY";
    private static final String PROFILE_SECRET_KEY_VALUE = "PROFILE_SECRET_KEY";
    private static final String TEST_ROLE_ARN = "TEST_ROLE_ARN";
    private static final String TEST_ROLE_EXTERNAL_ID = "TEST_EXTERNAL_ID";
    private static final String TEST_ROLE_SESSION_NAME = "TEST_ROLE_SESSION_NAME";
    private static final String SESSION_TOKEN = "SESSION_TOKEN";
    private static final String AWS_ROLE_ARN = "awsRoleArn";
    private static final String AWS_ROLE_EXTERNAL_ID = "awsRoleExternalId";
    private static final String AWS_ROLE_ACCESS_KEY_ID = "awsRoleAccessKeyId";
    private static final String AWS_ROLE_SECRET_ACCESS_KEY = "awsRoleSecretAccessKey";
    private static final String AWS_PROFILE_NAME = "awsProfileName";
    private static final String AWS_DEBUG_CREDS_NAME = "awsDebugCreds";
    private static final String AWS_STS_REGION_ENDPOINT = "awsStsRegionalEndpoint";
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
            STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(Collections.emptyMap());
            assertFalse(provider.getShouldDebugCreds());

            AwsCredentials credentials = provider.resolveCredentials();

            assertEquals(ACCESS_KEY_VALUE, credentials.accessKeyId());
            assertEquals(SECRET_KEY_VALUE, credentials.secretAccessKey());
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
            STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap);

            AwsCredentials credentials = provider.resolveCredentials();

            assertEquals(ACCESS_KEY_VALUE, credentials.accessKeyId());
            assertEquals(SECRET_KEY_VALUE, credentials.secretAccessKey());
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
            STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(Collections.emptyMap()) {
                protected AwsCredentialsProvider getDefaultProvider() {
                    return AwsCredentialsProviderChain.of(
                        EnvironmentVariableCredentialsProvider.create(),
                        SystemPropertyCredentialsProvider.create(),
                        WebIdentityTokenFileCredentialsProvider.create(),
                        ProfileCredentialsProvider.builder().profileFile(profileFile).build(),
                        ContainerCredentialsProvider.builder().build(),
                        InstanceProfileCredentialsProvider.create()
                    );
                }
            };

            AwsCredentials credentials = provider.resolveCredentials();

            assertEquals(PROFILE_ACCESS_KEY_VALUE, credentials.accessKeyId());
            assertEquals(PROFILE_SECRET_KEY_VALUE, credentials.secretAccessKey());
        }, TEST_PROFILE_NAME);
    }

    @Test
    public void testProfileName() {
        ProfileFile profileFile = getProfileFile();
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_PROFILE_NAME, "test_profile");
        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            ProfileCredentialsProvider createEnhancedProfileCredentialsProvider(String profileName) {
                assertEquals(TEST_PROFILE_NAME, profileName);
                return ProfileCredentialsProvider.builder()
                    .profileFile(profileFile)
                    .profileName(TEST_PROFILE_NAME)
                    .build();
            }
        };
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        assertEquals(PROFILE_ACCESS_KEY_VALUE, credentials.accessKeyId());
        assertEquals(PROFILE_SECRET_KEY_VALUE, credentials.secretAccessKey());
    }

    @Test
    public void testAwsRoleArn() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");


        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnWithAccessKey() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put(AWS_ROLE_ACCESS_KEY_ID, ACCESS_KEY_VALUE_TWO);
        optionsMap.put(AWS_ROLE_SECRET_ACCESS_KEY, SECRET_KEY_VALUE_TWO);
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilderWithCredentials(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentialsTwo(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnWithDebugCreds() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put(AWS_DEBUG_CREDS_NAME, "true");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");

        StsClient mockSts = Mockito.mock(StsClient.class);
        Mockito.when(mockSts.getCallerIdentity()).thenReturn(GetCallerIdentityResponse.builder().userId("TEST_USER_ID").account("TEST_ACCOUNT").arn("TEST_ARN").build());
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder) {
            StsClient getStsClientForDebuggingCreds(AwsCredentials credentials) {
                return mockSts;
            }
        };

        assertTrue(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
        Mockito.verify(mockSts, times(1)).getCallerIdentity();
    }

    @Test
    public void testEcsCredsWithDebugCredsNoAccessToSts_Succeed() {
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_DEBUG_CREDS_NAME, "true");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");


        ContainerCredentialsProvider mockEcsCredsProvider = Mockito.mock(ContainerCredentialsProvider.class);
        Mockito.when(mockEcsCredsProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsBasicCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO)));

        StsClient mockSts = Mockito.mock(StsClient.class);
        Mockito.when(mockSts.getCallerIdentity())
                .thenThrow(SdkClientException.create("TEST TEST"));

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return mockEcsCredsProvider;
            }

            StsClient getStsClientForDebuggingCreds(AwsCredentials credentials) {
                return mockSts;
            }
        };
        assertTrue(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();

        validateBasicCredentialsTwo(credentials);

        provider.close();
        Mockito.verify(mockSts, times(1)).getCallerIdentity();
        Mockito.verify(mockEcsCredsProvider, times(1)).resolveIdentity();
        Mockito.verifyNoMoreInteractions(mockEcsCredsProvider);
    }

    @Test
    public void testEc2CredsWithDebugCredsNoAccessToSts_Succeed() {
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_DEBUG_CREDS_NAME, "true");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");


        InstanceProfileCredentialsProvider mockEc2CredsProvider = Mockito.mock(InstanceProfileCredentialsProvider.class);
        Mockito.when(mockEc2CredsProvider.resolveIdentity())
            .thenAnswer(i -> CompletableFuture.completedFuture(AwsBasicCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO)));

        StsClient mockSts = Mockito.mock(StsClient.class);
        Mockito.when(mockSts.getCallerIdentity())
            .thenThrow(SdkClientException.create("TEST TEST"));

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return mockEc2CredsProvider;
            }

            StsClient getStsClientForDebuggingCreds(AwsCredentials credentials) {
                return mockSts;
            }
        };
        assertTrue(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();

        validateBasicCredentialsTwo(credentials);

        provider.close();
        Mockito.verify(mockSts, times(1)).getCallerIdentity();
        Mockito.verify(mockEc2CredsProvider, times(1)).resolveIdentity();
        Mockito.verifyNoMoreInteractions(mockEc2CredsProvider);
    }

    @Test
    public void testAwsRoleArnAndSessionName() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                TEST_ROLE_SESSION_NAME);
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnSessionNameAndStsRegion() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);
        optionsMap.put("awsStsRegion", "eu-west-1");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleRegionalCredentialProvider(String roleArn,
                                                                                    String sessionName, String stsRegion, String stsRegionalEndpoint) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(TEST_ROLE_SESSION_NAME, sessionName);
                assertEquals("eu-west-1", stsRegion);
                URI endpointConfiguration = buildEndpointConfiguration(Region.of(stsRegion), stsRegionalEndpoint);
                assertEquals("https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com", endpointConfiguration.toString());
                return mockStsRoleProvider;
            }
        };
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnSessionNameStsRegionAndRegionalEndpoint() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);
        optionsMap.put("awsStsRegion", "us-east-1");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleRegionalCredentialProvider(String roleArn,
                                                                                    String sessionName,
                                                                                    String stsRegion,
                                                                                    String stsRegionalEndpoint) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals("https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com", stsRegionalEndpoint);
                assertEquals(TEST_ROLE_SESSION_NAME, sessionName);
                assertEquals("us-east-1", stsRegion);
                URI endpointConfiguration = buildEndpointConfiguration(Region.of(stsRegion), stsRegionalEndpoint);
                assertEquals("https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com", endpointConfiguration.toString());
                return mockStsRoleProvider;
            }
        };
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnSessionNameStsRegionAndExternalId() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put(AWS_ROLE_EXTERNAL_ID, TEST_ROLE_EXTERNAL_ID);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);
        optionsMap.put("awsStsRegion", "eu-west-1");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                             String externalId,
                                                                             String sessionName,
                                                                             String stsRegion) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(TEST_ROLE_EXTERNAL_ID, externalId);
                assertEquals(TEST_ROLE_SESSION_NAME, sessionName);
                assertEquals("eu-west-1", stsRegion);
                URI endpointConfiguration = buildEndpointConfiguration(Region.of(stsRegion));
                assertEquals("https://sts.eu-west-1.amazonaws.com", endpointConfiguration.toString());
                return mockStsRoleProvider;
            }
        };
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testAwsRoleArnSessionNameStsRegionAndStsRegionalEndPoint() {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put("awsRoleSessionName", TEST_ROLE_SESSION_NAME);
        optionsMap.put("awsStsRegion", "us-east-1");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleRegionalCredentialProvider(String roleArn,
                                                                             String sessionName,
                                                                             String stsRegion,
                                                                             String stsRegionalEndpoint) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(TEST_ROLE_SESSION_NAME, sessionName);
                assertEquals("us-east-1", stsRegion);
                URI endpointConfiguration = buildEndpointConfiguration(Region.of(stsRegion), stsRegionalEndpoint);
                assertEquals("https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com", endpointConfiguration.toString());
                return mockStsRoleProvider;
            }
        };
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
    }

    @Test
    public void testProfileNameAndRoleArn() {
        ProfileFile profileFile = getProfileFile();
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO, SESSION_TOKEN)));

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_PROFILE_NAME, "test_profile");
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            ProfileCredentialsProvider createEnhancedProfileCredentialsProvider(String profileName) {
                assertEquals(TEST_PROFILE_NAME, profileName);
                return ProfileCredentialsProvider.builder().profileFile(profileFile)
                    .profileName(TEST_PROFILE_NAME)
                    .build();
            }

            StsAssumeRoleCredentialsProvider createSTSRoleRegionalCredentialProvider(String roleArn,
                                                                                    String sessionName, String stsRegion, String stsRegionalEndpoint) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals("aws-msk-iam-auth", sessionName);
                assertEquals("https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com", stsRegionalEndpoint);

                return mockStsRoleProvider;
            }
        };
        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder);
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        provider.close();

        assertEquals(PROFILE_ACCESS_KEY_VALUE, credentials.accessKeyId());
        assertEquals(PROFILE_SECRET_KEY_VALUE, credentials.secretAccessKey());
        Mockito.verify(mockStsRoleProvider, times(0)).resolveCredentials();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
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
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return EnvironmentVariableCredentialsProvider.create();
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        assertThrows(SdkClientException.class, () -> provider.resolveCredentials());

        Mockito.verify(mockStsRoleProvider, times(numExceptions)).resolveIdentity();
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
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        AwsCredentialsProvider mockEc2CredsProvider = setupMockEc2DefaultProviderWithRetriableExceptions(numExceptions);

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return mockEc2CredsProvider;
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        assertThrows(SdkClientException.class, () -> provider.resolveCredentials());

        Mockito.verify(mockEc2CredsProvider, times(numExceptions)).resolveIdentity();
        Mockito.verifyNoMoreInteractions(mockEc2CredsProvider);
    }

    @Test
    public void testEc2CredsWithOnrRetriableErrorsCustomZeroRetry_ThrowsException() {
        int numExceptions = 1;
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsMaxRetries", "0");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        AwsCredentialsProvider mockEc2CredsProvider = setupMockEc2DefaultProviderWithRetriableExceptions(numExceptions);

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return mockEc2CredsProvider;
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        assertThrows(SdkClientException.class, () -> provider.resolveCredentials());

        Mockito.verify(mockEc2CredsProvider, times(numExceptions)).resolveIdentity();
        Mockito.verifyNoMoreInteractions(mockEc2CredsProvider);
    }

    private void testEc2CredsWithRetriableErrorsCustomRetry(int numExceptions) {
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsMaxRetries", "5");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        AwsCredentialsProvider mockEc2CredsProvider = setupMockEc2DefaultProviderWithRetriableExceptions(numExceptions);

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return mockEc2CredsProvider;
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();

        validateBasicCredentialsTwo(credentials);

        provider.close();
        Mockito.verify(mockEc2CredsProvider, times(numExceptions + 1)).resolveIdentity();
        Mockito.verifyNoMoreInteractions(mockEc2CredsProvider);
    }

    @Test
    public void testEcsCredsWithSixRetriableErrorsCustomRetry_ThrowsException() {
        int numExceptions = 6;
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsMaxRetries", "5");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        AwsCredentialsProvider mockEcsCredsProvider = setupMockEcsDefaultProviderWithRetriableExceptions(numExceptions);

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return mockEcsCredsProvider;
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        assertThrows(SdkClientException.class, () -> provider.resolveCredentials());

        Mockito.verify(mockEcsCredsProvider, times(numExceptions)).resolveIdentity();
        Mockito.verifyNoMoreInteractions(mockEcsCredsProvider);
    }

    @Test
    public void testEcsCredsWithOnrRetriableErrorsCustomZeroRetry_ThrowsException() {
        int numExceptions = 1;
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsMaxRetries", "0");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        AwsCredentialsProvider mockEcsCredsProvider = setupMockEcsDefaultProviderWithRetriableExceptions(numExceptions);

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return mockEcsCredsProvider;
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        assertThrows(SdkClientException.class, () -> provider.resolveCredentials());

        Mockito.verify(mockEcsCredsProvider, times(numExceptions)).resolveIdentity();
        Mockito.verifyNoMoreInteractions(mockEcsCredsProvider);
    }

    private void testEcsCredsWithRetriableErrorsCustomRetry(int numExceptions) {
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsMaxRetries", "5");
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        AwsCredentialsProvider mockEcsCredsProvider = setupMockEcsDefaultProviderWithRetriableExceptions(numExceptions);

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(optionsMap) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return mockEcsCredsProvider;
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();

        validateBasicCredentialsTwo(credentials);

        provider.close();
        Mockito.verify(mockEcsCredsProvider, times(numExceptions + 1)).resolveIdentity();
        Mockito.verifyNoMoreInteractions(mockEcsCredsProvider);
    }

    private void testRoleCredsWithRetriableErrors(int numExceptions) {
        StsAssumeRoleCredentialsProvider mockStsRoleProvider = setupMockStsRoleCredentialsProviderWithRetriableExceptions(
                numExceptions);

        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put(AWS_ROLE_ARN, TEST_ROLE_ARN);
        optionsMap.put(AWS_STS_REGION_ENDPOINT, "https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com");

        STSAssumeRoleMSKCredentialProvider.ProviderBuilder providerBuilder = getProviderBuilder(mockStsRoleProvider, optionsMap,
                "aws-msk-iam-auth");

        STSAssumeRoleMSKCredentialProvider provider = new STSAssumeRoleMSKCredentialProvider(providerBuilder) {
            protected AwsCredentialsProvider getDefaultProvider() {
                return EnvironmentVariableCredentialsProvider.create();
            }
        };
        assertFalse(provider.getShouldDebugCreds());

        AwsCredentials credentials = provider.resolveCredentials();
        validateBasicSessionCredentials(credentials);

        provider.close();
        Mockito.verify(mockStsRoleProvider, times(numExceptions + 1)).resolveIdentity();
        Mockito.verify(mockStsRoleProvider, times(1)).close();
        Mockito.verifyNoMoreInteractions(mockStsRoleProvider);
    }

    private STSAssumeRoleMSKCredentialProvider.ProviderBuilder getProviderBuilder(StsAssumeRoleCredentialsProvider mockStsRoleProvider,
                                                                                  Map<String, String> optionsMap, String s) {
        return new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleRegionalCredentialProvider(String roleArn,
                                                                                    String sessionName, String stsRegion, String stsRegionalEndpoint) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(s, sessionName);
                assertEquals("https://vpce-4kujcrex.sts.us-east-1.vpce.amazonaws.com", stsRegionalEndpoint);

                return mockStsRoleProvider;
            }
        };
    }

    private STSAssumeRoleMSKCredentialProvider.ProviderBuilder getProviderBuilderWithCredentials(StsAssumeRoleCredentialsProvider mockStsRoleProvider,
                                                                                                 Map<String, String> optionsMap, String s) {
        return new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                                    String sessionName, String stsRegion,
                                                                                    AwsCredentialsProvider credentials) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(s, sessionName);
                return mockStsRoleProvider;
            }
        };
    }

    private STSAssumeRoleMSKCredentialProvider.ProviderBuilder getProviderBuilderWithStsRegionalCredentials(StsAssumeRoleCredentialsProvider mockStsRoleProvider,
                                                                                                            Map<String, String> optionsMap, String s) {
        return new STSAssumeRoleMSKCredentialProvider.ProviderBuilder(optionsMap) {
            StsAssumeRoleCredentialsProvider createSTSRoleRegionalCredentialProvider(String roleArn,
                                                                             String sessionName, String stsRegion,
                                                                             String stsRegionalEndpoint) {
                assertEquals(TEST_ROLE_ARN, roleArn);
                assertEquals(s, sessionName);
                return mockStsRoleProvider;
            }
        };
    }

    private void validateBasicSessionCredentials(AwsCredentials credentials) {
        assertTrue(credentials instanceof AwsSessionCredentials);
        AwsSessionCredentials sessionCredentials = (AwsSessionCredentials) credentials;
        assertEquals(ACCESS_KEY_VALUE, sessionCredentials.accessKeyId());
        assertEquals(SECRET_KEY_VALUE, sessionCredentials.secretAccessKey());
        assertEquals(SESSION_TOKEN, sessionCredentials.sessionToken());
    }

    private void validateBasicSessionCredentialsTwo(AwsCredentials credentials) {
        assertTrue(credentials instanceof AwsSessionCredentials);
        AwsSessionCredentials sessionCredentials = (AwsSessionCredentials) credentials;
        assertEquals(ACCESS_KEY_VALUE_TWO, sessionCredentials.accessKeyId());
        assertEquals(SECRET_KEY_VALUE_TWO, sessionCredentials.secretAccessKey());
        assertEquals(SESSION_TOKEN, sessionCredentials.sessionToken());
    }

    private void validateBasicCredentialsTwo(AwsCredentials credentials) {
        assertTrue(credentials instanceof AwsBasicCredentials);
        assertEquals(ACCESS_KEY_VALUE_TWO, credentials.accessKeyId());
        assertEquals(SECRET_KEY_VALUE_TWO, credentials.secretAccessKey());
    }

    private StsAssumeRoleCredentialsProvider setupMockStsRoleCredentialsProviderWithRetriableExceptions(int numErrors) {
        SdkException[] exceptionsToThrow = getSdkBaseExceptions(numErrors);

        StsAssumeRoleCredentialsProvider mockStsRoleProvider = Mockito
                .mock(StsAssumeRoleCredentialsProvider.class);
        Mockito.when(mockStsRoleProvider.resolveIdentity())
                .thenThrow(exceptionsToThrow)
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsSessionCredentials.create(ACCESS_KEY_VALUE, SECRET_KEY_VALUE, SESSION_TOKEN)));
        return mockStsRoleProvider;
    }

    private SdkException[] getSdkBaseExceptions(int numErrors) {
        final SdkException exceptionFromProvider = SdkClientException.create("TEST TEST TEST");
        return IntStream.range(0, numErrors).mapToObj(i -> exceptionFromProvider)
                .collect(Collectors.toList()).toArray(new SdkException[numErrors]);
    }

    private AwsCredentialsProvider setupMockEcsDefaultProviderWithRetriableExceptions(int numErrors) {
        SdkException[] exceptionsToThrow = getSdkBaseExceptions(numErrors);
        ContainerCredentialsProvider mockEcsProvider = Mockito.mock(ContainerCredentialsProvider.class);

        Mockito.when(mockEcsProvider.resolveIdentity())
                .thenThrow(exceptionsToThrow)
                .thenAnswer(i -> CompletableFuture.completedFuture(AwsBasicCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO)));
        return mockEcsProvider;
    }

    private AwsCredentialsProvider setupMockEc2DefaultProviderWithRetriableExceptions(int numErrors) {
        SdkException[] exceptionsToThrow = getSdkBaseExceptions(numErrors);
        InstanceProfileCredentialsProvider mockEc2Provider = Mockito.mock(InstanceProfileCredentialsProvider.class);

        Mockito.when(mockEc2Provider.resolveIdentity())
            .thenThrow(exceptionsToThrow)
            .thenAnswer(i -> CompletableFuture.completedFuture(AwsBasicCredentials.create(ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO)));
        return mockEc2Provider;
    }

    private ProfileFile getProfileFile() {
        return ProfileFile.builder()
            .content(new File(getProfileResourceURL().getFile()).toPath())
            .type(ProfileFile.Type.CREDENTIALS)
            .build();
    }

    private URL getProfileResourceURL() {
        return getClass().getClassLoader().getResource("profile_config_file");
    }

}
