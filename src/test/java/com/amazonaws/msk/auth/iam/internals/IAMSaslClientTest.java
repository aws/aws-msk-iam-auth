/*
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.msk.auth.iam.IAMClientCallbackHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.RandomStringUtils;
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
    private static final String VALID_HOSTNAME = "b-3.unit-test.abcdef.kafka.us-west-2.amazonaws.com";
    private static final String AWS_MSK_IAM = "AWS_MSK_IAM";
    private static final String ACCESS_KEY_VALUE = "ACCESS_KEY_VALUE";
    private static final String SECRET_KEY_VALUE = "SECRET_KEY_VALUE";
    private static final String ACCESS_KEY_VALUE_TWO = "ACCESS_KEY_VALUE_TWO";
    private static final String SECRET_KEY_VALUE_TWO = "SECRET_KEY_VALUE_TWO";
    private static final String RESPONSE_VERSION = "2020_10_22";

    private static final BasicAWSCredentials BASIC_AWS_CREDENTIALS = new BasicAWSCredentials(ACCESS_KEY_VALUE, SECRET_KEY_VALUE);

    @Test
    public void testCompleteValidExchange() throws IOException, ParseException {
        IAMSaslClient saslClient = getSuccessfulIAMClient(getIamClientCallbackHandler());
        runValidExchangeForSaslClient(saslClient, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
    }

    private void runValidExchangeForSaslClient(IAMSaslClient saslClient, String accessKey, String secretKey) {
        assertEquals(AWS_MSK_IAM, saslClient.getMechanismName());
        assertTrue(saslClient.hasInitialResponse());
        SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials(() -> {
            try {
                byte[] response = saslClient.evaluateChallenge(new byte[]{});

                SignedPayloadValidatorUtils
                        .validatePayload(response,
                                AuthenticationRequestParams
                                        .create(VALID_HOSTNAME, new BasicAWSCredentials(accessKey, secretKey)));
                assertFalse(saslClient.isComplete());

                String requestId = RandomStringUtils.randomAlphabetic(10);
                saslClient.evaluateChallenge(getServerResponse(RESPONSE_VERSION, requestId));
                assertTrue(saslClient.isComplete());
                assertEquals(requestId, saslClient.getResponseRequestId());
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            }
        }, accessKey, secretKey);
    }

    private byte [] getServerResponse(String version, String requestId) throws JsonProcessingException {
        AuthenticationResponse response = new AuthenticationResponse(version, requestId);
        return new ObjectMapper().writeValueAsBytes(response);
    }

    @Test
    public void testMultipleSaslClients() throws IOException, ParseException {
        IAMClientCallbackHandler cbh = getIamClientCallbackHandler();

        //test the first Sasl client with 1 set of credentials.
        IAMSaslClient saslClient1 = getSuccessfulIAMClient(cbh);
        runValidExchangeForSaslClient(saslClient1, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);

        //test second sasl client with another set of credentials
        IAMSaslClient saslClient2 = getSuccessfulIAMClient(cbh);
        runValidExchangeForSaslClient(saslClient2, ACCESS_KEY_VALUE_TWO, SECRET_KEY_VALUE_TWO);
    }

    private IAMClientCallbackHandler getIamClientCallbackHandler() {
        IAMClientCallbackHandler cbh = new IAMClientCallbackHandler();
        cbh.configure(Collections.EMPTY_MAP, AWS_MSK_IAM, Collections.emptyList());
        return cbh;
    }

    @Test
    public void testNonEmptyChallenge() throws SaslException {
        SaslClient saslClient = getSuccessfulIAMClient(getIamClientCallbackHandler());
        SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials(() -> {
                    assertThrows(SaslException.class, () -> saslClient.evaluateChallenge(new byte[]{2, 3}));
                }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
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
    public void testInvalidServerResponse() throws SaslException {
        SaslClient saslClient = getSuccessfulIAMClient(getIamClientCallbackHandler());
        assertEquals(AWS_MSK_IAM, saslClient.getMechanismName());
        assertTrue(saslClient.hasInitialResponse());
        SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials(() -> {
            try {
                byte[] response = saslClient.evaluateChallenge(new byte[]{});
            } catch (SaslException e) {
                throw new RuntimeException("Test failed", e);
            }
            assertFalse(saslClient.isComplete());

            assertThrows(SaslException.class, () -> saslClient.evaluateChallenge(new byte[]{3, 4}));
            assertFalse(saslClient.isComplete());

            assertThrows(IllegalSaslStateException.class, () -> saslClient.evaluateChallenge(new byte[]{}));
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
    }

    @Test
    public void testInvalidResponseVersion() throws SaslException {
        SaslClient saslClient = getSuccessfulIAMClient(getIamClientCallbackHandler());
        SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials(() -> {
            try {
                byte[] response = saslClient.evaluateChallenge(new byte[]{});
            } catch (SaslException e) {
                throw new RuntimeException("Test failed", e);
            }
            assertFalse(saslClient.isComplete());

            assertThrows(SaslException.class, () -> saslClient.evaluateChallenge(getResponseWithInvalidVersion()));
            assertFalse(saslClient.isComplete());

            assertThrows(IllegalSaslStateException.class, () -> saslClient.evaluateChallenge(new byte[]{}));
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
    }

    private byte[] getResponseWithInvalidVersion() {
        AuthenticationResponse response = new AuthenticationResponse(RESPONSE_VERSION, "TEST_REQUEST_ID");
        try {
            return new ObjectMapper().writeValueAsString(response).replaceAll(RESPONSE_VERSION,"INVALID_VERSION").getBytes();
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Test failed", e);
        }
    }

    @Test
    public void testEmptyServerResponse() throws SaslException {
        SaslClient saslClient = getSuccessfulIAMClient(getIamClientCallbackHandler());
        assertEquals(AWS_MSK_IAM, saslClient.getMechanismName());
        assertTrue(saslClient.hasInitialResponse());
        SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials(() -> {
            try {
                byte[] response = saslClient.evaluateChallenge(new byte[]{});
            } catch (SaslException e) {
                throw new RuntimeException("Test failed", e);
            }
            assertFalse(saslClient.isComplete());

            assertThrows(SaslException.class, () -> saslClient.evaluateChallenge(new byte[]{}));
            assertFalse(saslClient.isComplete());
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
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

    private IAMSaslClient getSuccessfulIAMClient(IAMClientCallbackHandler cbh) throws SaslException {
        return getIAMClient(() -> cbh);
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

    private IAMSaslClient getIAMClient(Supplier<IAMClientCallbackHandler> handlerSupplier) throws SaslException {
        return (IAMSaslClient )new IAMSaslClient.IAMSaslClientFactory()
                .createSaslClient(new String[]{AWS_MSK_IAM}, "AUTH_ID", "PROTOCOL", VALID_HOSTNAME,
                        Collections.emptyMap(),
                        handlerSupplier.get());
    }

}
