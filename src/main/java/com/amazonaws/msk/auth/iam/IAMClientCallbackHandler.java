package com.amazonaws.msk.auth.iam;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.msk.auth.iam.internals.AWSCredentialsCallback;
import com.amazonaws.msk.auth.iam.internals.MSKCredentialProvider;
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
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
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
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
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
