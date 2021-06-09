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
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.EC2ContainerCredentialsProviderWrapper;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.auth.WebIdentityTokenCredentialsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
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
 * 2. A particular AWS IAM Role and optional AWS IAM role session name:
 *     awsRoleArn={IAM Role ARN}, awsRoleSessionName = {session name}
 * 3. If no options is provided, the DefaultAWSCredentialsProviderChain is used.
 * The DefaultAWSCredentialProviderChain can be pointed to credentials in many different ways:
 * <a href="https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html">Working with AWS Credentials</a>
 */
public class MSKCredentialProvider implements AWSCredentialsProvider, AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(MSKCredentialProvider.class);
    private static final String AWS_PROFILE_NAME_KEY = "awsProfileName";
    private static final String AWS_ROLE_ARN_KEY = "awsRoleArn";
    private static final String AWS_ROLE_SESSION_KEY = "awsRoleSessionName";

    private final List<AutoCloseable> closeableProviders;
    private final AWSCredentialsProvider compositeDelegate;

    public MSKCredentialProvider(Map<String, ?> options) {
        this(new ProviderBuilder(options).getProviders());
    }

    MSKCredentialProvider(ProviderBuilder builder) {
        this(builder.getProviders());
    }

    MSKCredentialProvider(List<AWSCredentialsProvider> providers) {
        List<AWSCredentialsProvider> delegateList = new ArrayList<>(providers);
        delegateList.add(getDefaultProvider());
        compositeDelegate = new AWSCredentialsProviderChain(delegateList);
        closeableProviders = providers.stream().filter(p -> p instanceof AutoCloseable).map(p -> (AutoCloseable) p)
                .collect(Collectors.toList());
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
        return compositeDelegate.getCredentials();
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
                return createSTSRoleCredentialProvider((String) p, sessionName);
            });
        }

        STSAssumeRoleSessionCredentialsProvider createSTSRoleCredentialProvider(String roleArn,
                String sessionName) {
            return new STSAssumeRoleSessionCredentialsProvider.Builder(roleArn, sessionName).build();
        }
    }
}
