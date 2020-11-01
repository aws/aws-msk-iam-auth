package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class AWS4RequestSignerTest {
    private static final String VALID_HOSTNAME = "b-3.statatat-test.bhowhu.kafka.us-west-2.amazonaws.com";

    @Test
    public void demoTest() throws IOException {
        AWS4SignedPayloadGenerator signer = new AWS4SignedPayloadGenerator();
        String signedRequest = new String(signer.signedPayload(AuthenticationRequestParams.create(VALID_HOSTNAME,
                new DefaultAWSCredentialsProviderChain().getCredentials())));
        System.out.println(signedRequest);
    }
}
