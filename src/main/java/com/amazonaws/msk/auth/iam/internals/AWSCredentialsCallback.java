package com.amazonaws.msk.auth.iam.internals;


import com.amazonaws.auth.AWSCredentials;

import javax.security.auth.callback.Callback;

/**
 * This class is used to pass AWSCredentials from the IAMCredentialCallbackHandler to the IAMSaslClient.
 */
public class AWSCredentialsCallback implements Callback {
    private AWSCredentials awsCredentials = null;
    private Exception loadingException = null;

    public AWSCredentials getAwsCredentials() {
        return awsCredentials;
    }

    public void setAwsCredentials(AWSCredentials awsCredentials) {
        this.awsCredentials = awsCredentials;
        this.loadingException = null;
    }

    public Exception getLoadingException() {
        return loadingException;
    }

    public void setLoadingException(Exception loadingException) {
        this.loadingException = loadingException;
        this.awsCredentials = null;
    }

    public boolean isSuccessful() {
        return awsCredentials != null;
    }
}
