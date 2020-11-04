package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import lombok.Getter;
import lombok.NonNull;

import javax.security.auth.callback.Callback;

/**
 * This class is used to pass AWSCredentials to the {@link IAMSaslClient}.
 * It is processed by the {@link com.amazonaws.msk.auth.iam.IAMClientCallbackHandler}.
 * If the callback handler succeeds, it sets the AWSCredentials. If the callback handler fails to load the credentials,
 * it sets the loading exception.
 */
public class AWSCredentialsCallback implements Callback {
    @Getter
    private AWSCredentials awsCredentials = null;
    @Getter
    private Exception loadingException = null;

    public void setAwsCredentials(@NonNull AWSCredentials awsCredentials) {
        this.awsCredentials = awsCredentials;
        this.loadingException = null;
    }

    public void setLoadingException(@NonNull Exception loadingException) {
        this.loadingException = loadingException;
        this.awsCredentials = null;
    }

    public boolean isSuccessful() {
        return awsCredentials != null;
    }
}
