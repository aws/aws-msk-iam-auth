package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.msk.auth.iam.IAMLoginModule;
import org.apache.kafka.common.errors.IllegalSaslStateException;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

public class IAMSaslClient implements SaslClient {

    private static final Logger log = LoggerFactory.getLogger(IAMSaslClient.class);

    enum State {
        SEND_CLIENT_FIRST_MESSAGE, RECEIVE_SERVER_RESPONSE, COMPLETE, FAILED
    }

    private final String mechanism;
    private final CallbackHandler cbh;
    private final String serverName;
    private State state;

    public IAMSaslClient(String mechanism, CallbackHandler cbh, String serverName) {
        this.mechanism = mechanism;
        this.cbh = cbh;
        this.serverName = serverName;
        setState(State.SEND_CLIENT_FIRST_MESSAGE);
    }

    @Override
    public String getMechanismName() {
        return mechanism;
    }

    @Override
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        if (log.isDebugEnabled()) {
            log.debug("State {} at start of evaluating challenge", state);
        }
        try {
            switch (state) {
                case SEND_CLIENT_FIRST_MESSAGE:
                    if (!isChallengeEmpty(challenge)) {
                        throw new SaslException("Expects an empty challenge");
                    }
                    AWSCredentialsCallback callback = new AWSCredentialsCallback();
                    cbh.handle(new Callback[]{callback});
                    if (callback.isSuccessful()) {
                        //TODO: signing etc
                        log.debug(callback.getAwsCredentials().getAWSAccessKeyId());
                    } else {
                        throw new SaslException("Failed to find AWS IAM Credentials", callback.getLoadingException());
                    }
                    return new byte[0];
                case RECEIVE_SERVER_RESPONSE:
                    //TODO: process and log response
                    setState(State.COMPLETE);
                    return null;
                default:
                    throw new IllegalSaslStateException("Challenge received in unexpected state " + state);
            }
        } catch (SaslException se) {
            setState(State.FAILED);
            throw se;
        } catch (IOException | UnsupportedCallbackException e) {
            setState(State.FAILED);
            throw new SaslException("Exception while evaluating challenge", e);
        } finally {
            if (log.isDebugEnabled()) {
                log.debug("State {} at end of evaluating challenge", state);
            }
        }
    }

    @Override
    public boolean isComplete() {
        return false;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (!isComplete()) {
            throw new IllegalStateException("Authentication exchange has not completed");
        }
        return Arrays.copyOfRange(incoming, offset, offset + len);
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (!isComplete()) {
            throw new IllegalStateException("Authentication exchange has not completed");
        }
        return Arrays.copyOfRange(outgoing, offset, offset + len);
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        return null;
    }

    @Override
    public void dispose() throws SaslException {

    }

    private void setState(State state) {
        log.debug("Setting SASL/{} client state to {}", mechanism, state);
        this.state = state;
    }

    private static boolean isChallengeEmpty(byte[] challenge) {
        if (challenge != null && challenge.length > 0) {
            return false;
        }
        return true;
    }

    public static class IAMSaslClientFactory implements SaslClientFactory {
        @Override
        public SaslClient createSaslClient(String[] mechanisms,
                String authorizationId,
                String protocol,
                String serverName,
                Map<String, ?> props,
                CallbackHandler cbh) throws SaslException {
            for (String mechanism : mechanisms) {
                if (IAMLoginModule.MECHANISM.equals(mechanism)) {
                    return new IAMSaslClient(mechanism, cbh, serverName);
                }
            }
            throw new SaslException(
                    "Requested mechanisms " + Arrays.asList(mechanisms) + " not supported. The supported" +
                            "mechanism is " + IAMLoginModule.MECHANISM);
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> props) {
            return new String[]{IAMLoginModule.MECHANISM};
        }
    }

}
