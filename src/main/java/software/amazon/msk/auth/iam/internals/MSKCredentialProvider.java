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
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * This AWS Credential Provider is used to load up AWS Credentials based on options provided on the Jaas config line.
 * As as an example
 * sasl.jaas.config = IAMLoginModule required awsProfileName={profile name};
 * The currently supported options are:
 * 1. A particular AWS Credential profile: awsProfileName={profile name}
 * 2. If no options is provided, the DefaultAWSCredentialsProviderChain is used.
 * The DefaultAWSCredentialProviderChain can be pointed to credentials in many different ways:
 * <a href="https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html">Working with AWS Credentials</a>
 */
public class MSKCredentialProvider implements AWSCredentialsProvider {
    private static final Logger log = LoggerFactory.getLogger(MSKCredentialProvider.class);
    private static final String AWS_PROFILE_NAME_KEY = "awsProfileName";
    private final AWSCredentialsProvider delegate;

    public MSKCredentialProvider(Map<String, ?> options) {
        this(options, getProfileProvider(options));
    }

    MSKCredentialProvider(Map<String, ?> options,
            Optional<ProfileCredentialsProvider> profileCredentialsProvider) {
        final List delegateList = getListOfDelegates(profileCredentialsProvider);
        delegate = new AWSCredentialsProviderChain(delegateList);
        if (log.isDebugEnabled()) {
            log.debug("Number of options to configure credential provider {}", options.size());
        }
    }

    private List getListOfDelegates(Optional<ProfileCredentialsProvider> profileCredentialsProvider) {
        final List delegateList = new ArrayList<>();
        profileCredentialsProvider.ifPresent(delegateList::add);
        delegateList.add(new DefaultAWSCredentialsProviderChain());
        return delegateList;
    }

    private static Optional<ProfileCredentialsProvider> getProfileProvider(Map<String, ?> options) {
        return Optional.ofNullable(options.get(AWS_PROFILE_NAME_KEY)).map(p -> {
            if (log.isDebugEnabled()) {
                log.debug("Profile name {}", p);
            }
            return new ProfileCredentialsProvider((String) p);
        });
    }

    @Override
    public AWSCredentials getCredentials() {
        return delegate.getCredentials();
    }

    @Override
    public void refresh() {
        delegate.refresh();
    }
}
