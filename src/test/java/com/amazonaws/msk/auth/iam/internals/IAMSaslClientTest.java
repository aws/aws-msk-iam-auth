package com.amazonaws.msk.auth.iam.internals;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.junit.jupiter.api.Test;

import javax.security.sasl.SaslException;

public class IAMSaslClientTest {

//    class FailureAMClientCallbackHandler extends AuthenticateCallbackHandler {
//
//    }

    @Test
    public void demoTest() throws SaslException {
        IAMSaslClient saslClient = new IAMSaslClient("MECH", new IAMSaslClientCallbackHandler(), "SERVER");
        saslClient.evaluateChallenge(new byte[]{});

    }


}
