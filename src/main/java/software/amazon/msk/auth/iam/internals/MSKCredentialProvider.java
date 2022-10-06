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

import com.amazonaws.SdkClientException;
import com.amazonaws.auth.*;

import lombok.AccessLevel;
import lombok.Getter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.core.retry.RetryPolicyContext;
import software.amazon.awssdk.core.retry.backoff.BackoffStrategy;
import software.amazon.awssdk.core.retry.backoff.FullJitterBackoffStrategy;
import software.amazon.awssdk.core.retry.conditions.RetryOnExceptionsCondition;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;


/**
 * This AWS Credential Provider is used to load up AWS Credentials based on options provided on the Jaas config line.
 * As an example
 * sasl.jaas.config = IAMLoginModule required awsProfileName={profile name};
 * The currently supported options are:
 * 1. A particular AWS Credential profile: awsProfileName={profile name}
 * 2. A particular AWS IAM Role and optionally AWS IAM role session name and AWS region for the STS endpoint:
 *     awsRoleArn={IAM Role ARN}, awsRoleSessionName={session name}, awsStsRegion={region name}. Credentials from the
 *     DefaultCredentialsProvider are used to assume the specified IAM Role.
 * 3. Optional arguments to configure retries when we fail to load credentials:
 *     awsMaxRetries={Maximum number of retries}, awsMaxBackOffTimeMs={Maximum back off time between retries in ms}
 * 4. Optional argument to help debug credentials used to establish connections:
 *     awsDebugCreds={true|false}
 * 5. If no options is provided, the DefaultCredentialsProvider is used.
 * TODO: update
 * The DefaultAWSCredentialProviderChain can be pointed to credentials in many different ways:
 * <a href="https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html">Working with AWS Credentials</a>
 */
public class MSKCredentialProvider implements AWSCredentialsProvider, AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(MSKCredentialProvider.class);
    private static final String AWS_PROFILE_NAME_KEY = "awsProfileName";
    private static final String AWS_ROLE_ARN_KEY = "awsRoleArn";
    private static final String AWS_ROLE_SESSION_KEY = "awsRoleSessionName";
    private static final String AWS_STS_REGION = "awsStsRegion";
    private static final String AWS_DEBUG_CREDS_KEY = "awsDebugCreds";
    private static final String AWS_MAX_RETRIES = "awsMaxRetries";
    private static final String AWS_MAX_BACK_OFF_TIME_MS = "awsMaxBackOffTimeMs";
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final int DEFAULT_MAX_BACK_OFF_TIME_MS = 5000;
    private static final int BASE_DELAY = 500;

    private final List<AutoCloseable> closeableProviders;
    private final AwsCredentialsProvider compositeDelegate;
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

    MSKCredentialProvider(List<AwsCredentialsProvider> providers,
            Boolean shouldDebugCreds,
            String stsRegion,
            int maxRetries,
            int maxBackOffTimeMs) {
        List<AwsCredentialsProvider> delegateList = new ArrayList<>(providers);
        delegateList.add(getDefaultProvider());
        compositeDelegate = AwsCredentialsProviderChain.builder().credentialsProviders(delegateList).build();
        closeableProviders = providers.stream().filter(p -> p instanceof AutoCloseable).map(p -> (AutoCloseable) p)
                .collect(Collectors.toList());
        this.shouldDebugCreds = shouldDebugCreds;
        this.stsRegion = stsRegion;
        if (maxRetries > 0) {
            BackoffStrategy retryBackoffStrategy = FullJitterBackoffStrategy.builder().baseDelay(Duration.ofMillis(BASE_DELAY)).maxBackoffTime(Duration.ofMillis(maxBackOffTimeMs)).build();
            this.retryPolicy = RetryPolicy.builder().backoffStrategy(retryBackoffStrategy)
                    .numRetries(maxRetries)
                    .throttlingBackoffStrategy(retryBackoffStrategy)
                    .retryCondition(RetryOnExceptionsCondition.create(software.amazon.awssdk.core.exception.SdkClientException.class, SdkClientException.class))
                    .additionalRetryConditionsAllowed(false)
                    .retryCapacityCondition(null)
                    .build();
        } else {
            this.retryPolicy = RetryPolicy.none();
        }
    }

    //We want to override the ProfileCredentialsProvider with the EnhancedProfileCredentialsProvider
    protected AwsCredentialsProvider getDefaultProvider() {
        return DefaultCredentialsProvider.builder().asyncCredentialUpdateEnabled(true).build();
    }

    @Override
    public AWSCredentials getCredentials() {
        AwsCredentials credentials = loadCredentialsWithRetry();
        if (credentials != null && shouldDebugCreds && log.isDebugEnabled()) {
            logCallerIdentity(credentials);
        }
        return  getAwsCredentialsV1(credentials);
    }

    private AwsCredentials loadCredentialsWithRetry() {
        RetryPolicyContext retryPolicyContext = RetryPolicyContext.builder().build();
        boolean shouldTry = true;
        try {
            while (shouldTry) {
                try {
                    AwsCredentials credentials = compositeDelegate.resolveCredentials();
                    if (credentials == null) {
                        throw software.amazon.awssdk.core
                                .exception.SdkClientException.create("Composite delegate returned empty credentials.");
                    }
                    return credentials;
                } catch (SdkException se) {
                    log.warn("Exception loading credentials. Retry Attempts: {}",
                            retryPolicyContext.retriesAttempted(), se);
                    retryPolicyContext = createRetryPolicyContext(se, retryPolicyContext.retriesAttempted());
                    shouldTry = retryPolicy.aggregateRetryCondition().shouldRetry(retryPolicyContext);
                    if (shouldTry) {
                        Thread.sleep(retryPolicy.backoffStrategy().computeDelayBeforeNextRetry(retryPolicyContext).toMillis());
                        retryPolicyContext = createRetryPolicyContext(retryPolicyContext.exception(),
                                retryPolicyContext.retriesAttempted() + 1);
                    } else {
                        throw new SdkClientException(se.getMessage());
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

    private RetryPolicyContext createRetryPolicyContext(SdkException sdkException, int retriesAttempted) {
        return RetryPolicyContext.builder().exception(sdkException)
                .retriesAttempted(retriesAttempted).build();
    }

    private void logCallerIdentity(AwsCredentials credentials) {
        try {
            StsClient stsClient = getStsClientForDebuggingCreds(credentials);
            GetCallerIdentityResponse response = stsClient.getCallerIdentity();
            log.debug("The identity of the credentials is {}", response.toString());
        } catch (Exception e) {
            //If we run into an exception logging the caller identity, we should log the exception but
            //continue running.
            log.warn("Error identifying caller identity. If this is not transient, does this application have"
                    + "access to AWS STS?", e);
        }
    }

    private static AWSCredentials getAwsCredentialsV1(AwsCredentials credentialsV2) {
        if (credentialsV2 == null) {
            return null;
        }
        if (credentialsV2 instanceof AwsSessionCredentials) {
            AwsSessionCredentials sessionCredentialsV2 = (AwsSessionCredentials) credentialsV2;
            return new BasicSessionCredentials(sessionCredentialsV2.accessKeyId(),
                    sessionCredentialsV2.secretAccessKey(), sessionCredentialsV2.sessionToken());
        }

        return new BasicAWSCredentials(credentialsV2.accessKeyId(), credentialsV2.secretAccessKey());
    }

    StsClient getStsClientForDebuggingCreds(AwsCredentials credentials) {
        return StsClient.builder().region(Region.of(stsRegion))
                .credentialsProvider(StaticCredentialsProvider.create(credentials)).build();
    }

    @Override
    public void refresh() {
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

        public List<AwsCredentialsProvider> getProviders() {
            List<AwsCredentialsProvider> providers = new ArrayList<>();
            getProfileProvider().ifPresent(providers::add);
            getStsRoleProvider().ifPresent(providers::add);
            return providers;
        }

        public Boolean shouldDebugCreds() {
            return Optional.ofNullable(optionsMap.get(AWS_DEBUG_CREDS_KEY)).map(d -> d.equals("true")).orElse(false);
        }

        public String getStsRegion() {
            return Optional.ofNullable((String)optionsMap.get(AWS_STS_REGION))
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

        private Optional<ProfileCredentialsProvider> getProfileProvider() {
            return Optional.ofNullable(optionsMap.get(AWS_PROFILE_NAME_KEY)).map(p -> {
                if (log.isDebugEnabled()) {
                    log.debug("Profile name {}", p);
                }
                return createProfileCredentialsProvider((String) p);
            });
        }

        ProfileCredentialsProvider createProfileCredentialsProvider(String p) {
            return ProfileCredentialsProvider.create(p);
        }

        private Optional<StsAssumeRoleCredentialsProvider> getStsRoleProvider() {
            return Optional.ofNullable(optionsMap.get(AWS_ROLE_ARN_KEY)).map(p -> {
                if (log.isDebugEnabled()) {
                    log.debug("Role ARN {}", p);
                }
                String sessionName = Optional.ofNullable((String) optionsMap.get(AWS_ROLE_SESSION_KEY))
                        .orElse("aws-msk-iam-auth");
                String stsRegion = getStsRegion();
                return createSTSRoleCredentialProvider((String) p, sessionName, stsRegion);
            });
        }

        StsAssumeRoleCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                                                                         String sessionName, String stsRegion) {
            StsClient stsClient = getStsClient(stsRegion);
            AssumeRoleRequest assumeRoleRequest = AssumeRoleRequest.builder()
                    .roleArn(roleArn).roleSessionName(sessionName).build();
            return StsAssumeRoleCredentialsProvider.builder().stsClient(stsClient)
                    .refreshRequest(assumeRoleRequest).asyncCredentialUpdateEnabled(true).build();
        }
    }

    private static StsClient getStsClient(String stsRegion) {
        StsClient  stsClient = StsClient.builder().region(Region.of(stsRegion)).build();
        return stsClient;
    }


}
