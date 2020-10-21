package com.amazonaws.msk.auth.iam.internals;


import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import org.junit.jupiter.api.Test;

import java.time.Instant;

public class AWS4RequestSignerTest {

    @Test
    public void demoTest() {
        AWS4RequestSigner signer = new AWS4RequestSigner();
        signer.sign(AuthenticationRequestParams.create("b-3.statatat-test.bhowhu.kafka.us-west-2.amazonaws.com",
                new DefaultAWSCredentialsProviderChain().getCredentials()));
    }
}
