package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.msk.auth.iam.IAMLoginModule;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class IAMSaslClientCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger log = LoggerFactory.getLogger(IAMSaslClientCallbackHandler.class);

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!IAMLoginModule.MECHANISM.equals(saslMechanism)) {
            throw new IllegalArgumentException("Unexpected SASL mechanism: " + saslMechanism);
        }
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

    protected void handleCallback(AWSCredentialsCallback callback) {
        try {
            callback.setAwsCredentials(DefaultAWSCredentialsProviderChain.getInstance().getCredentials());
        } catch (Exception e) {

            callback.setLoadingException(e);
        }
    }
}
