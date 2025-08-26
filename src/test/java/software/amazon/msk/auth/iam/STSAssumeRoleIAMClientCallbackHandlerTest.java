package software.amazon.msk.auth.iam;

import org.junit.jupiter.api.Test;
import software.amazon.msk.auth.iam.internals.AWSCredentialsCallback;
import software.amazon.msk.auth.iam.internals.SystemPropertyCredentialsUtils;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

public class STSAssumeRoleIAMClientCallbackHandlerTest {

    private static final String ACCESS_KEY_VALUE = "ACCESS_KEY_VALUE";
    private static final String SECRET_KEY_VALUE = "SECRET_KEY_VALUE";

    @Test
    public void testDefaultCredentials() throws IOException, UnsupportedCallbackException {
        STSAssumeRoleIAMClientCallbackHandler clientCallbackHandler = new STSAssumeRoleIAMClientCallbackHandler();
        clientCallbackHandler.configure(Collections.emptyMap(), "AWS_MSK_IAM", Collections.emptyList());
        SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials(() -> {
            AWSCredentialsCallback callback = new AWSCredentialsCallback();
            try {
                clientCallbackHandler.handle(new Callback[]{callback});
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }

            assertTrue(callback.isSuccessful());
            assertEquals(ACCESS_KEY_VALUE, callback.getAwsCredentials().accessKeyId());
            assertEquals(SECRET_KEY_VALUE, callback.getAwsCredentials().secretAccessKey());
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
    }

    @Test
    public void testDifferentMechanism() {
        STSAssumeRoleIAMClientCallbackHandler clientCallbackHandler = new STSAssumeRoleIAMClientCallbackHandler();
        assertThrows(IllegalArgumentException.class, () -> clientCallbackHandler
                .configure(Collections.emptyMap(), "SOME_OTHER_MECHANISM", Collections.emptyList()));
    }

    @Test
    public void testDifferentCallback() {
        STSAssumeRoleIAMClientCallbackHandler clientCallbackHandler = new STSAssumeRoleIAMClientCallbackHandler();
        UnsupportedCallbackException callbackException = assertThrows(UnsupportedCallbackException.class,
                () -> clientCallbackHandler.handle(new Callback[]{new Callback() {
                }}));
        assertTrue(callbackException.getMessage().startsWith("Unsupported"));
    }

    @Test
    public void testDebugClassString() {
        String debug1 = STSAssumeRoleIAMClientCallbackHandler.debugClassString(this.getClass());
        assertTrue(debug1.contains("software.amazon.msk.auth.iam.STSAssumeRoleIAMClientCallbackHandlerTest"));
        STSAssumeRoleIAMClientCallbackHandler clientCallbackHandler = new STSAssumeRoleIAMClientCallbackHandler();
        String debug2 = STSAssumeRoleIAMClientCallbackHandler.debugClassString(clientCallbackHandler.getClass());
        assertTrue(debug2.contains("software.amazon.msk.auth.iam.STSAssumeRoleIAMClientCallbackHandler"));
    }

}