package com.amazonaws.msk.auth.iam.internals;


import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class AWS4RequestSignerTest {

    @Test
    public void demoTest() throws IOException {
        AWS4SignedPayloadGenerator signer = new AWS4SignedPayloadGenerator();
        String signedRequest = new String(signer.signedPayload(AuthenticationRequestParams.create("b-3.statatat-test.bhowhu.kafka.us-west-2.amazonaws.com",
                new DefaultAWSCredentialsProviderChain().getCredentials())));
        System.out.println(signedRequest);
    }
}
