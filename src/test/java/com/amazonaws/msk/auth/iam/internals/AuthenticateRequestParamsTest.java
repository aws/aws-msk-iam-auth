package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AuthenticateRequestParamsTest {
    private static final String VALID_HOSTNAME = "b-3.unit-test.abcdef.kafka.us-west-2.amazonaws.com";
    private static final String HOSTNAME_NO_REGIOM = "abcd.efgh.com";
    private AWSCredentials credentials;
    private static final String ACCESS_KEY = "ACCESS_KEY";
    private static final String SECRET_KEY = "SECRET_KEY";

    @BeforeEach
    public void setup() {
        credentials = new BasicAWSCredentials(ACCESS_KEY, SECRET_KEY);
    }

    @Test
    public void testAllProperties() {
        AuthenticationRequestParams params = AuthenticationRequestParams.create(VALID_HOSTNAME, credentials);

        assertEquals("us-west-2", params.getRegion().getName());
        assertEquals("kafka-cluster", params.getServiceScope());
        assertEquals(VALID_HOSTNAME, params.getHost());
        assertEquals(ACCESS_KEY, params.getAwsCredentials().getAWSAccessKeyId());
        assertEquals(SECRET_KEY, params.getAwsCredentials().getAWSSecretKey());
    }

    @Test
    public void testInvalidHost() {
        assertThrows(IllegalArgumentException.class,
                () -> AuthenticationRequestParams.create(HOSTNAME_NO_REGIOM, credentials));
    }
}
