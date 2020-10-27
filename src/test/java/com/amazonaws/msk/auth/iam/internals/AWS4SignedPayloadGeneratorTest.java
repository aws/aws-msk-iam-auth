package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.text.ParseException;

public class AWS4SignedPayloadGeneratorTest {
    public static final String VALID_HOSTNAME = "b-3.unit-test.abcdef.kafka.us-west-2.amazonaws.com";
    private AWSCredentials credentials;
    private static final String ACCESS_KEY = "ACCESS_KEY";
    private static final String SECRET_KEY = "SECRET_KEY";

    @BeforeEach
    public void setup() {
        credentials = new BasicAWSCredentials(ACCESS_KEY, SECRET_KEY);
    }

    @Test
    public void testSigning() throws IOException, ParseException {
        AuthenticationRequestParams params = AuthenticationRequestParams.create(VALID_HOSTNAME, credentials);
        AWS4SignedPayloadGenerator generator = new AWS4SignedPayloadGenerator();
        byte[] signedPayload = generator.signedPayload(params);

        assertNotNull(signedPayload);
        SignedPayloadValidatorUtils.validatePayload(signedPayload, params);
    }


}
