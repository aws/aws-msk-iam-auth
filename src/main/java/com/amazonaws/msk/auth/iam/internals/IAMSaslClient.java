package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.msk.auth.iam.IAMLoginModule;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.util.Arrays;
import java.util.Map;

public class IAMSaslClient implements SaslClient {
    private final String mechanism;
    private final CallbackHandler cbh;
    private final String serverName;

    public IAMSaslClient(String mechanism, CallbackHandler cbh, String serverName) {
        this.mechanism = mechanism;
        this.cbh = cbh;
        this.serverName = serverName;
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
        //TODO: fill it in
        return new byte[0];
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
