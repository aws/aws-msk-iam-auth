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
package com.amazonaws.msk.auth.iam;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.msk.auth.iam.internals.AWSCredentialsCallback;
import com.amazonaws.msk.auth.iam.internals.MSKCredentialProvider;
import lombok.NonNull;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * This client callback handler is used to extract AWSCredentials.
 * The credentials are based on JaasConfig options passed to {@link IAMLoginModule}.
 * If config options are provided the {@link MSKCredentialProvider} is used.
 * If no config options are provided it uses the DefaultAWSCredentialsProviderChain.
 */
public class IAMClientCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger log = LoggerFactory.getLogger(IAMClientCallbackHandler.class);
    private AWSCredentialsProvider provider;

    @Override
    public void configure(Map<String, ?> configs,
            @NonNull String saslMechanism,
            @NonNull List<AppConfigurationEntry> jaasConfigEntries) {
        if (!IAMLoginModule.MECHANISM.equals(saslMechanism)) {
            throw new IllegalArgumentException("Unexpected SASL mechanism: " + saslMechanism);
        }
        final Optional<AppConfigurationEntry> configEntry = jaasConfigEntries.stream()
                .filter(j -> IAMLoginModule.class.getCanonicalName().equals(j.getLoginModuleName())).findFirst();
        provider = configEntry.map(c -> (AWSCredentialsProvider) new MSKCredentialProvider(c.getOptions()))
                .orElse(DefaultAWSCredentialsProviderChain.getInstance());
    }

    @Override
    public void close() {
    }

    @Override
    public void handle(@NonNull Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof AWSCredentialsCallback) {
                handleCallback((AWSCredentialsCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    protected void handleCallback(AWSCredentialsCallback callback) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Selecting provider {} to load credentials", provider.getClass().getName());
        }
        try {
            provider.refresh();
            callback.setAwsCredentials(provider.getCredentials());
        } catch (Exception e) {
            callback.setLoadingException(e);
        }
    }
}
