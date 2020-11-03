package com.amazonaws.msk.auth.iam;

import com.amazonaws.msk.auth.iam.internals.AWSCredentialsCallback;
import com.amazonaws.msk.auth.iam.internals.SystemPropertyCredentialsUtils;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.junit.jupiter.api.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class IAMClientCallbackHandlerTest {
    private static final String ACCESS_KEY_VALUE = "ACCESS_KEY_VALUE";
    private static final String SECRET_KEY_VALUE = "SECRET_KEY_VALUE";

    @Test
    public void testDefaultCredentials() throws IOException, UnsupportedCallbackException {
        IAMClientCallbackHandler clientCallbackHandler = new IAMClientCallbackHandler();
        clientCallbackHandler.configure(Collections.emptyMap(), "AWS_MSK_IAM", Collections.emptyList());
        SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials(() -> {
            AWSCredentialsCallback callback = new AWSCredentialsCallback();
            try {
                clientCallbackHandler.handle(new Callback[]{callback});
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }

            assertTrue(callback.isSuccessful());
            assertEquals(ACCESS_KEY_VALUE, callback.getAwsCredentials().getAWSAccessKeyId());
            assertEquals(SECRET_KEY_VALUE, callback.getAwsCredentials().getAWSSecretKey());
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
    }

    @Test
    public void testDifferentMechanism() {
        IAMClientCallbackHandler clientCallbackHandler = new IAMClientCallbackHandler();
        assertThrows(IllegalArgumentException.class, () -> clientCallbackHandler
                .configure(Collections.emptyMap(), "SOME_OTHER_MECHANISM", Collections.emptyList()));
    }

    @Test
    public void testDifferentCallback() {
        IAMClientCallbackHandler clientCallbackHandler = new IAMClientCallbackHandler();
        assertThrows(UnsupportedCallbackException.class,
                () -> clientCallbackHandler.handle(new Callback[]{new Callback() {
                }}));
    }


}
