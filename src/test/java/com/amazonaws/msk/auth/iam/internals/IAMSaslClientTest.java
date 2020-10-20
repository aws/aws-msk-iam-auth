package com.amazonaws.msk.auth.iam.internals;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionMetadataFactory;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.junit.jupiter.api.Test;

import javax.security.sasl.SaslException;

public class IAMSaslClientTest {

//    class FailureAMClientCallbackHandler extends AuthenticateCallbackHandler {
//
//    }

    @Test
    public void demoTest() throws SaslException {
        //IAMSaslClient saslClient = new IAMSaslClient("MECH", new IAMSaslClientCallbackHandler(), "SERVER");
        //saslClient.evaluateChallenge(new byte[]{});
        Region region = RegionMetadataFactory.create().tryGetRegionByEndpointDnsSuffix("b-3.sayantac-test.bhowhu.kafka.us-west-2.amazonaws.com");
        System.out.println(region);
    }


}
