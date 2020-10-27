package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.msk.auth.iam.IAMClientCallbackHandler;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.common.errors.IllegalSaslStateException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.text.ParseException;
import java.util.Collections;
import java.util.function.Supplier;

public class IAMSaslClientTest {
    public static final String VALID_HOSTNAME = "b-3.unit-test.abcdef.kafka.us-west-2.amazonaws.com";
    public static final String AWS_MSK_IAM = "AWS_MSK_IAM";
    public static final BasicAWSCredentials BASIC_AWS_CREDENTIALS = new BasicAWSCredentials("ACCESS_KEY", "SECRET_KEY");

    @Test
    public void testCompleteValidExchange() throws IOException, ParseException {
        SaslClient saslClient = getSuccessfulIAMClient();
        assertEquals(AWS_MSK_IAM, saslClient.getMechanismName());
        assertTrue(saslClient.hasInitialResponse());

        byte[] response = saslClient.evaluateChallenge(new byte[]{});

        SignedPayloadValidatorUtils
                .validatePayload(response, AuthenticationRequestParams.create(VALID_HOSTNAME, BASIC_AWS_CREDENTIALS));
        assertFalse(saslClient.isComplete());

        saslClient.evaluateChallenge(new byte[]{});
        assertTrue(saslClient.isComplete());
    }

    @Test
    public void testNonEmptyChallenge() throws SaslException {
        SaslClient saslClient = getSuccessfulIAMClient();
        assertThrows(SaslException.class, () -> saslClient.evaluateChallenge(new byte[]{2, 3}));
        assertFalse(saslClient.isComplete());
    }

    @Test
    public void testFailedCallback() throws SaslException {
        SaslClient saslClient = getFailureIAMClient();
        assertThrows(SaslException.class, () -> saslClient.evaluateChallenge(new byte[]{}));
        assertFalse(saslClient.isComplete());
    }

    @Test
    public void testThrowingCallback() throws SaslException {
        SaslClient saslClient = getThrowingIAMClient();
        assertThrows(SaslException.class, () -> saslClient.evaluateChallenge(new byte[]{}));
        assertFalse(saslClient.isComplete());
    }

    @Test
    public void testNonEmptyServerResponse() throws SaslException {
        SaslClient saslClient = getSuccessfulIAMClient();
        assertEquals(AWS_MSK_IAM, saslClient.getMechanismName());
        assertTrue(saslClient.hasInitialResponse());

        byte[] response = saslClient.evaluateChallenge(new byte[]{});

        assertFalse(saslClient.isComplete());

        assertThrows(SaslException.class, () -> saslClient.evaluateChallenge(new byte[]{3, 4}));
        assertFalse(saslClient.isComplete());

        assertThrows(IllegalSaslStateException.class, () -> saslClient.evaluateChallenge(new byte[]{}));
    }

    @Test
    public void testFactoryMechanisms() {
        assertArrayEquals(new String[]{AWS_MSK_IAM},
                new IAMSaslClient.IAMSaslClientFactory().getMechanismNames(Collections.emptyMap()));
    }

    @Test
    public void testInvalidMechanism() {

        assertThrows(SaslException.class, () -> new IAMSaslClient.IAMSaslClientFactory()
                .createSaslClient(new String[]{AWS_MSK_IAM + "BAD"}, "AUTH_ID", "PROTOCOL", VALID_HOSTNAME,
                        Collections.emptyMap(),
                        new SuccessfulIAMCallbackHandler(BASIC_AWS_CREDENTIALS)));
    }

    private static class SuccessfulIAMCallbackHandler extends IAMClientCallbackHandler {
        private final BasicAWSCredentials basicAWSCredentials;

        public SuccessfulIAMCallbackHandler(BasicAWSCredentials basicAWSCredentials) {
            this.basicAWSCredentials = basicAWSCredentials;
        }

        @Override
        protected void handleCallback(AWSCredentialsCallback callback) {
            callback.setAwsCredentials(basicAWSCredentials);
        }
    }

    private SaslClient getSuccessfulIAMClient() throws SaslException {
        return getIAMClient(() -> new SuccessfulIAMCallbackHandler(BASIC_AWS_CREDENTIALS));
    }

    private SaslClient getFailureIAMClient() throws SaslException {
        return getIAMClient(() -> new IAMClientCallbackHandler() {
            @Override
            protected void handleCallback(AWSCredentialsCallback callback) {
                callback.setLoadingException(new IllegalArgumentException("TEST Exception"));
            }
        });
    }

    private SaslClient getThrowingIAMClient() throws SaslException {
        return getIAMClient(() -> new IAMClientCallbackHandler() {
            @Override
            protected void handleCallback(AWSCredentialsCallback callback) throws IOException {
                throw new IOException("TEST IO Exception");
            }
        });
    }

    private SaslClient getIAMClient(Supplier<IAMClientCallbackHandler> handlerSupplier) throws SaslException {
        return new IAMSaslClient.IAMSaslClientFactory()
                .createSaslClient(new String[]{AWS_MSK_IAM}, "AUTH_ID", "PROTOCOL", VALID_HOSTNAME,
                        Collections.emptyMap(),
                        handlerSupplier.get());
    }

}
