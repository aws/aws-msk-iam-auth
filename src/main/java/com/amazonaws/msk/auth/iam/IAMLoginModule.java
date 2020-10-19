package com.amazonaws.msk.auth.iam;

import com.amazonaws.msk.auth.iam.internals.IAMSaslClientProvider;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Map;

/**
 *
 */
public class IAMLoginModule implements LoginModule {
    public static final String MECHANISM = "AWS_MSK_IAM";

    static {
        IAMSaslClientProvider.initialize();
    }

    @Override
    public void initialize(Subject subject,
            CallbackHandler callbackHandler,
            Map<String, ?> sharedState,
            Map<String, ?> options) {

    }

    @Override
    public boolean login() throws LoginException {
        return false;
    }

    @Override
    public boolean commit() throws LoginException {
        return false;
    }

    @Override
    public boolean abort() throws LoginException {
        return false;
    }

    @Override
    public boolean logout() throws LoginException {
        return false;
    }
}