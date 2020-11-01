package com.amazonaws.msk.auth.iam;

import com.amazonaws.msk.auth.iam.internals.IAMSaslClientProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Map;

/**
 * This Login Module is used to register the {@link IAMSaslClientProvider}.
 * The module is a no-op for other purposes.
 */
public class IAMLoginModule implements LoginModule {
    public static final String MECHANISM = "AWS_MSK_IAM";

    private static final Logger log = LoggerFactory.getLogger(IAMLoginModule.class);

    static {
        IAMSaslClientProvider.initialize();
    }

    @Override
    public void initialize(Subject subject,
            CallbackHandler callbackHandler,
            Map<String, ?> sharedState,
            Map<String, ?> options) {
        if (log.isDebugEnabled()) {
            log.debug("IAMLoginModule initialized");
        }
    }

    @Override
    public boolean login() throws LoginException {
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return false;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }
}
