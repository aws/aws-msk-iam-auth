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

import com.amazonaws.SdkBaseException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.EC2ContainerCredentialsProviderWrapper;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.auth.WebIdentityTokenCredentialsProvider;
import com.amazonaws.retry.PredefinedBackoffStrategies;
import com.amazonaws.retry.v2.AndRetryCondition;
import com.amazonaws.retry.v2.MaxNumberOfRetriesCondition;
import com.amazonaws.retry.v2.RetryOnExceptionsCondition;
import com.amazonaws.retry.v2.RetryPolicy;
import com.amazonaws.retry.v2.RetryPolicyContext;
import com.amazonaws.retry.v2.SimpleRetryPolicy;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import lombok.AccessLevel;
import lombok.Getter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;


/**
 * This AWS Credential Provider is used to load up AWS Credentials based on options provided on the Jaas config line.
 * As as an example
 * sasl.jaas.config = IAMLoginModule required awsProfileName={profile name};
 * The currently supported options are:
 * 1. A particular AWS Credential profile: awsProfileName={profile name}
 * 2. A particular AWS IAM Role, with optional access key id, secret key and session token OR optional external id,
 *    and optionally AWS IAM role session name and AWS region for the STS endpoint:
 *     awsRoleArn={IAM Role ARN}, awsRoleAccessKeyId={access key id}, awsRoleSecretAccessKey={secret access key},
 *     awsRoleSessionToken={session token}, awsRoleSessionName={session name}, awsStsRegion={region name}
 * 3. Optional arguments to configure retries when we fail to load credentials:
 *     awsMaxRetries={Maximum number of retries}, awsMaxBackOffTimeMs={Maximum back off time between retries in ms}
 * 4. Optional argument to help debug credentials used to establish connections:
 *     awsDebugCreds={true|false}
 * 5. If no options is provided, the DefaultAWSCredentialsProviderChain is used.
 * The DefaultAWSCredentialProviderChain can be pointed to credentials in many different ways:
 * <a href="https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html">Working with AWS Credentials</a>
 */
public class MSKCredentialProvider implements AWSCredentialsProvider, AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(MSKCredentialProvider.class);
    private static final String AWS_PROFILE_NAME_KEY = "awsProfileName";
    private static final String AWS_ROLE_ARN_KEY = "awsRoleArn";
    private static final String AWS_ROLE_EXTERNAL_ID = "awsRoleExternalId";
    private static final String AWS_ROLE_ACCESS_KEY_ID = "awsRoleAccessKeyId";
    private static final String AWS_ROLE_SECRET_ACCESS_KEY = "awsRoleSecretAccessKey";
    private static final String AWS_ROLE_SESSION_KEY = "awsRoleSessionName";
    private static final String AWS_ROLE_SESSION_TOKEN = "awsRoleSessionToken";
    private static final String AWS_STS_REGION = "awsStsRegion";
    private static final String AWS_DEBUG_CREDS_KEY = "awsDebugCreds";
    private static final String AWS_MAX_RETRIES = "awsMaxRetries";
    private static final String AWS_MAX_BACK_OFF_TIME_MS = "awsMaxBackOffTimeMs";
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final int DEFAULT_MAX_BACK_OFF_TIME_MS = 5000;
    private static final int BASE_DELAY = 500;

    private final List<AutoCloseable> closeableProviders;
    private final AWSCredentialsProvider compositeDelegate;
    @Getter(AccessLevel.PACKAGE)
    private final Boolean shouldDebugCreds;
    private final String stsRegion;
    private final RetryPolicy retryPolicy;

    public MSKCredentialProvider(Map<String, ?> options) {
        this(new ProviderBuilder(options));
    }

    MSKCredentialProvider(ProviderBuilder builder) {
        this(builder.getProviders(), builder.shouldDebugCreds(), builder.getStsRegion(), builder.getMaxRetries(),
                builder.getMaxBackOffTimeMs());
    }

    MSKCredentialProvider(List<AWSCredentialsProvider> providers,
            Boolean shouldDebugCreds,
            String stsRegion,
            int maxRetries,
            int maxBackOffTimeMs) {
        List<AWSCredentialsProvider> delegateList = new ArrayList<>(providers);
        delegateList.add(getDefaultProvider());
        compositeDelegate = new AWSCredentialsProviderChain(delegateList);
        closeableProviders = providers.stream().filter(p -> p instanceof AutoCloseable).map(p -> (AutoCloseable) p)
                .collect(Collectors.toList());
        this.shouldDebugCreds = shouldDebugCreds;
        this.stsRegion = stsRegion;
        if (maxRetries > 0) {
            this.retryPolicy = new SimpleRetryPolicy(
                    new AndRetryCondition(new RetryOnExceptionsCondition(Collections.singletonList(
                            SdkClientException.class)), new MaxNumberOfRetriesCondition(maxRetries)),
                    new PredefinedBackoffStrategies.FullJitterBackoffStrategy(BASE_DELAY, maxBackOffTimeMs));
        } else {
            this.retryPolicy = new SimpleRetryPolicy((c) -> false,
                    new PredefinedBackoffStrategies.FullJitterBackoffStrategy(BASE_DELAY, maxBackOffTimeMs));
        }
    }

    //We want to override the ProfileCredentialsProvider with the EnhancedProfileCredentialsProvider
    protected AWSCredentialsProviderChain getDefaultProvider() {
        return new AWSCredentialsProviderChain(new EnvironmentVariableCredentialsProvider(),
                new SystemPropertiesCredentialsProvider(),
                WebIdentityTokenCredentialsProvider.create(),
                new EnhancedProfileCredentialsProvider(),
                new EC2ContainerCredentialsProviderWrapper());
    }

    @Override
    public AWSCredentials getCredentials() {
        AWSCredentials credentials = loadCredentialsWithRetry();
        if (credentials != null && shouldDebugCreds && log.isDebugEnabled()) {
            logCallerIdentity(credentials);
        }
        return  credentials;
    }

    private AWSCredentials loadCredentialsWithRetry() {
        RetryPolicyContext retryPolicyContext = RetryPolicyContext.builder().build();
        boolean shouldTry = true;
        try {
            while (shouldTry) {
                try {
                    AWSCredentials credentials = compositeDelegate.getCredentials();
                    if (credentials == null) {
                        throw new SdkClientException("Composite delegate returned empty credentials.");
                    }
                    return credentials;
                } catch (SdkBaseException se) {
                    log.warn("Exception loading credentials. Retry Attempts: {}",
                            retryPolicyContext.retriesAttempted(), se);
                    retryPolicyContext = createRetryPolicyContext(se, retryPolicyContext.retriesAttempted());
                    shouldTry = retryPolicy.shouldRetry(retryPolicyContext);
                    if (shouldTry) {
                        Thread.sleep(retryPolicy.computeDelayBeforeNextRetry(retryPolicyContext));
                        retryPolicyContext = createRetryPolicyContext(retryPolicyContext.exception(),
                                retryPolicyContext.retriesAttempted() + 1);
                    } else {
                        throw se;
                    }
                }
            }
            throw new SdkClientException(
                    "loadCredentialsWithRetry in unexpected location " + retryPolicyContext.totalRequests(),
                    retryPolicyContext.exception());
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting for credentials.", ie);
        }
    }

    private RetryPolicyContext createRetryPolicyContext(SdkBaseException sdkException, int retriesAttempted) {
        return RetryPolicyContext.builder().exception(sdkException)
                .retriesAttempted(retriesAttempted).build();
    }

    private void logCallerIdentity(AWSCredentials credentials) {
        try {
            AWSSecurityTokenService stsClient = getStsClientForDebuggingCreds(credentials);
            GetCallerIdentityResult response = stsClient.getCallerIdentity(new GetCallerIdentityRequest());
            log.debug("The identity of the credentials is {}", response.toString());
        } catch (Exception e) {
            //If we run into an exception logging the caller identity, we should log the exception but
            //continue running.
            log.warn("Error identifying caller identity. If this is not transient, does this application have"
                    + "access to AWS STS?", e);
        }
    }

    AWSSecurityTokenService getStsClientForDebuggingCreds(AWSCredentials credentials) {
        return AWSSecurityTokenServiceClientBuilder.standard()
                    .withRegion(stsRegion)
                    .withCredentials(new AWSCredentialsProvider() {
                        @Override
                        public AWSCredentials getCredentials() {
                            return credentials;
                        }

                        @Override
                        public void refresh() {

                        }
                    })
                    .build();
    }

    @Override
    public void refresh() {
        compositeDelegate.refresh();
    }

    @Override
    public void close() {
        closeableProviders.stream().forEach(p -> {
            try {
                p.close();
            } catch (Exception e) {
                log.warn("Error closing credential provider", e);
            }
        });
    }

    public static class ProviderBuilder {
        private final Map<String, ?> optionsMap;

        public ProviderBuilder(Map<String, ?> optionsMap) {
            this.optionsMap = optionsMap;
            if (log.isDebugEnabled()) {
                log.debug("Number of options to configure credential provider {}", optionsMap.size());
            }
        }

        public List<AWSCredentialsProvider> getProviders() {
            List<AWSCredentialsProvider> providers = new ArrayList<>();
            getProfileProvider().ifPresent(providers::add);
            getStsRoleProvider().ifPresent(providers::add);
            return providers;
        }

        public Boolean shouldDebugCreds() {
            return Optional.ofNullable(optionsMap.get(AWS_DEBUG_CREDS_KEY)).map(d -> d.equals("true")).orElse(false);
        }

        public String getStsRegion() {
            return Optional.ofNullable((String) optionsMap.get(AWS_STS_REGION))
                    .orElse("aws-global");
        }

        public int getMaxRetries() {
            return Optional.ofNullable(optionsMap.get(AWS_MAX_RETRIES)).map(p -> (String) p).map(Integer::parseInt)
                    .orElse(DEFAULT_MAX_RETRIES);
        }

        public int getMaxBackOffTimeMs() {
            return Optional.ofNullable(optionsMap.get(AWS_MAX_BACK_OFF_TIME_MS)).map(p -> (String) p)
                    .map(Integer::parseInt)
                    .orElse(DEFAULT_MAX_BACK_OFF_TIME_MS);
        }

        private Optional<EnhancedProfileCredentialsProvider> getProfileProvider() {
            return Optional.ofNullable(optionsMap.get(AWS_PROFILE_NAME_KEY)).map(p -> {
                if (log.isDebugEnabled()) {
                    log.debug("Profile name {}", p);
                }
                return createEnhancedProfileCredentialsProvider((String) p);
            });
        }

        EnhancedProfileCredentialsProvider createEnhancedProfileCredentialsProvider(String p) {
            return new EnhancedProfileCredentialsProvider(p);
        }

        private Optional<STSAssumeRoleSessionCredentialsProvider> getStsRoleProvider() {
            return Optional.ofNullable(optionsMap.get(AWS_ROLE_ARN_KEY)).map(p -> {
                if (log.isDebugEnabled()) {
                    log.debug("Role ARN {}", p);
                }
                String sessionName = Optional.ofNullable((String) optionsMap.get(AWS_ROLE_SESSION_KEY))
                        .orElse("aws-msk-iam-auth");
                String stsRegion = getStsRegion();

                String accessKey = (String) optionsMap.getOrDefault(AWS_ROLE_ACCESS_KEY_ID, null);
                String secretKey = (String) optionsMap.getOrDefault(AWS_ROLE_SECRET_ACCESS_KEY, null);
                String sessionToken = (String) optionsMap.getOrDefault(AWS_ROLE_SESSION_TOKEN, null);
                String externalId = (String) optionsMap.getOrDefault(AWS_ROLE_EXTERNAL_ID, null);
                if (accessKey != null && secretKey != null) {
                    AWSCredentialsProvider credentials = new AWSStaticCredentialsProvider(
                            sessionToken != null
                                    ? new BasicSessionCredentials(accessKey, secretKey, sessionToken)
                                    : new BasicAWSCredentials(accessKey, secretKey));

                    return createSTSRoleCredentialProvider((String) p, sessionName, stsRegion, credentials);
                }
                else if (externalId != null) {
                    return createSTSRoleCredentialProvider((String) p, externalId, sessionName, stsRegion);
                }

                return createSTSRoleCredentialProvider((String) p, sessionName, stsRegion);
            });
        }

        STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                                String sessionName, String stsRegion) {
            AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                    .withRegion(stsRegion)
                    .build();
            return new STSAssumeRoleSessionCredentialsProvider.Builder(roleArn, sessionName)
                    .withStsClient(stsClient)
                    .build();
        }

        STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                                String sessionName, String stsRegion,
                                                                                AWSCredentialsProvider credentials) {
            AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                    .withRegion(stsRegion)
                    .withCredentials(credentials)
                    .build();

            return new STSAssumeRoleSessionCredentialsProvider.Builder(roleArn, sessionName)
                    .withStsClient(stsClient)
                    .build();
        }

        STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                                String externalId,
                                                                                String sessionName,
                                                                                String stsRegion) {
            AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                    .withRegion(stsRegion)
                    .build();

            return new STSAssumeRoleSessionCredentialsProvider.Builder(roleArn, sessionName)
                    .withStsClient(stsClient)
                    .withExternalId(externalId)
                    .build();
        }
    }

}
