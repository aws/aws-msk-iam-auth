package software.amazon.msk.auth.iam;


import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.msk.auth.iam.internals.AWSCredentialsCallback;
import software.amazon.msk.auth.iam.internals.STSAssumeRoleMSKCredentialProvider;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class STSAssumeRoleIAMClientCallbackHandler extends IAMClientCallbackHandler {
    private static final Logger log = LoggerFactory.getLogger(STSAssumeRoleIAMClientCallbackHandler.class);
    private AwsCredentialsProvider provider;

    @Override
    public void configure(Map<String, ?> configs,
                          @NonNull String saslMechanism,
                          @NonNull List<AppConfigurationEntry> jaasConfigEntries) {
        if (!IAMLoginModule.MECHANISM.equals(saslMechanism)) {
            throw new IllegalArgumentException("Unexpected SASL mechanism: " + saslMechanism);
        }
        final Optional<AppConfigurationEntry> configEntry = jaasConfigEntries.stream()
                .filter(j -> IAMLoginModule.class.getCanonicalName().equals(j.getLoginModuleName())).findFirst();
        provider = configEntry.map(c -> (AwsCredentialsProvider) new STSAssumeRoleMSKCredentialProvider(c.getOptions()))
                .orElse(DefaultCredentialsProvider.create());
        log.info("Successfully retrieved Temp Credentials access key, secrete key");
    }

    @Override
    public void close() {
        try {
            if (provider instanceof AutoCloseable) {
                ((AutoCloseable) provider).close();
            }
        } catch (Exception e) {
            log.warn("Error closing provider", e);
        }
    }

    @Override
    public void handle(@NonNull Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (log.isDebugEnabled()) {
                log.debug("Type information for callback: " + debugClassString(callback.getClass()) + " from "
                        + debugClassString(this.getClass()));
            }
            if (callback instanceof AWSCredentialsCallback) {
                handleCallback((AWSCredentialsCallback) callback);
            } else {
                String message = "Unsupported callback type: " + debugClassString(callback.getClass()) + " from "
                        + debugClassString(this.getClass());
                //We are breaking good practice and logging as well as throwing since this is where client side
                //integrations might have trouble. Depending on the client framework either logging or throwing might
                //surface the error more easily to the user.
                log.error(message);
                throw new UnsupportedCallbackException(callback, message);
            }
        }
    }

    protected static String debugClassString(Class<?> clazz) {
        return "class: " + clazz.getName() + " classloader: " + clazz.getClassLoader().toString();
    }

    protected void handleCallback(AWSCredentialsCallback callback) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Selecting provider {} to load credentials", provider.getClass().getName());
        }

        try {
            callback.setAwsCredentials(provider.resolveCredentials());
            log.info("Credentials are set in the callback handler");
        } catch (Exception e) {
            callback.setLoadingException(e);
        }


    }
}
