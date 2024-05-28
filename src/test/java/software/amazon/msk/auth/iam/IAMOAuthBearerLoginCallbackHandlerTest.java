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
package software.amazon.msk.auth.iam;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.apache.kafka.common.security.scram.ScramCredentialCallback;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.http.auth.aws.internal.signer.util.SignerConstant;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class IAMOAuthBearerLoginCallbackHandlerTest {
    private static final String ACCESS_KEY_VALUE = "ACCESS_KEY_VALUE";
    private static final String SECRET_KEY_VALUE = "SECRET_KEY_VALUE";
    private static final String SESSION_TOKEN = "SESSION_TOKEN";
    private static final String TEST_REGION = "us-west-1";

    @Test
    public void configureWithInvalidMechanismShouldFail() {
        // Given
        IAMOAuthBearerLoginCallbackHandler iamOAuthBearerLoginCallbackHandler
                = new IAMOAuthBearerLoginCallbackHandler();
        // When & Then
        Assertions.assertThrows(IllegalArgumentException.class, () -> iamOAuthBearerLoginCallbackHandler.configure(
                Collections.emptyMap(), "SCRAM-SHA-512", Collections.emptyList()));
    }

    @Test
    public void handleWithoutConfigureShouldThrow() {
        // Given
        IAMOAuthBearerLoginCallbackHandler iamoAuthBearerLoginCallbackHandler
                = new IAMOAuthBearerLoginCallbackHandler();
        // When & Then
        Assertions.assertThrows(IllegalStateException.class,
                                () -> iamoAuthBearerLoginCallbackHandler.handle(new Callback[]{new OAuthBearerTokenCallback()}));
    }

    @Test
    public void handleWithDifferentCallbackShouldThrow() {
        // Given
        IAMOAuthBearerLoginCallbackHandler iamoAuthBearerLoginCallbackHandler
                = new IAMOAuthBearerLoginCallbackHandler();
        iamoAuthBearerLoginCallbackHandler.configure(
                Collections.emptyMap(), OAuthBearerLoginModule.OAUTHBEARER_MECHANISM, Collections.emptyList());
        // When & Then
        Assertions.assertThrows(UnsupportedCallbackException.class,
                                () -> iamoAuthBearerLoginCallbackHandler.handle(new Callback[]{new ScramCredentialCallback()}));
    }

    @Test
    public void handleWithTokenValuePresentShouldThrow() {
        // Given
        IAMOAuthBearerLoginCallbackHandler iamoAuthBearerLoginCallbackHandler
                = new IAMOAuthBearerLoginCallbackHandler();
        iamoAuthBearerLoginCallbackHandler.configure(
                Collections.emptyMap(), OAuthBearerLoginModule.OAUTHBEARER_MECHANISM, Collections.emptyList());
        OAuthBearerTokenCallback callback = new OAuthBearerTokenCallback();
        callback.token(getTestToken("token"));
        // When & Then
        Assertions.assertThrows(IllegalArgumentException.class,
                                () -> iamoAuthBearerLoginCallbackHandler.handle(new Callback[]{callback}));
    }

    @Test
    public void handleWithDefaultCredentials() throws IOException, UnsupportedCallbackException, URISyntaxException, ParseException {
        // Given
        IAMOAuthBearerLoginCallbackHandler iamoAuthBearerLoginCallbackHandler
                = new IAMOAuthBearerLoginCallbackHandler();
        iamoAuthBearerLoginCallbackHandler.configure(
                Collections.emptyMap(), OAuthBearerLoginModule.OAUTHBEARER_MECHANISM, Collections.emptyList());

        System.setProperty("aws.accessKeyId", ACCESS_KEY_VALUE);
        System.setProperty("aws.secretAccessKey", SECRET_KEY_VALUE);
        System.setProperty("aws.sessionToken", SESSION_TOKEN);
        System.setProperty("aws.region", TEST_REGION);

        OAuthBearerTokenCallback callback = new OAuthBearerTokenCallback();
        // When
        iamoAuthBearerLoginCallbackHandler.handle(new Callback[]{callback});
        // Then
        assertTokenValidity(callback.token(), TEST_REGION, ACCESS_KEY_VALUE, SESSION_TOKEN);
        cleanUp();
    }

    @Test
    public void testGovCloudRegionHandler() throws IOException, UnsupportedCallbackException, URISyntaxException, ParseException {
        // Given
        IAMOAuthBearerLoginCallbackHandler iamoAuthBearerLoginCallbackHandler
                = new IAMOAuthBearerLoginCallbackHandler();
        iamoAuthBearerLoginCallbackHandler.configure(
                Collections.emptyMap(), OAuthBearerLoginModule.OAUTHBEARER_MECHANISM, Collections.emptyList());

        System.setProperty("aws.accessKeyId", ACCESS_KEY_VALUE);
        System.setProperty("aws.secretAccessKey", SECRET_KEY_VALUE);
        System.setProperty("aws.sessionToken", SESSION_TOKEN);
        System.setProperty("aws.region", "us-gov-west-2");

        OAuthBearerTokenCallback callback = new OAuthBearerTokenCallback();
        // When
        iamoAuthBearerLoginCallbackHandler.handle(new Callback[]{callback});
        // Then
        assertTokenValidity(callback.token(), "us-gov-west-2", ACCESS_KEY_VALUE, SESSION_TOKEN);
        cleanUp();
    }

    @Test
    public void handleWithProfileCredentials() throws IOException, UnsupportedCallbackException, URISyntaxException, ParseException {
        // Given
        final String accessKey = "PROFILE_ACCESS_KEY";
        final String secretKey = "PROFILE_SECRET_KEY";
        final String sessionToken = "PROFILE_SESSION_TOKEN";
        final String profileName = "dev";
        IAMOAuthBearerLoginCallbackHandler iamoAuthBearerLoginCallbackHandler
                = new IAMOAuthBearerLoginCallbackHandler();
        iamoAuthBearerLoginCallbackHandler.configure(
                Collections.singletonMap("awsProfileName", profileName), OAuthBearerLoginModule.OAUTHBEARER_MECHANISM, Collections.emptyList());

        System.setProperty("aws.accessKeyId", accessKey);
        System.setProperty("aws.secretAccessKey", secretKey);
        System.setProperty("aws.sessionToken", sessionToken);
        System.setProperty("aws.profile", profileName);
        System.setProperty("aws.region", TEST_REGION);

        OAuthBearerTokenCallback callback = new OAuthBearerTokenCallback();
        // When
        iamoAuthBearerLoginCallbackHandler.handle(new Callback[]{callback});
        // Then
        assertTokenValidity(callback.token(), TEST_REGION, accessKey, sessionToken);
        cleanUp();
    }

    @Test
    public void testDebugClassString() {
        String debug1 = IAMOAuthBearerLoginCallbackHandler.debugClassString(this.getClass());
        assertTrue(debug1.contains("software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandlerTest"));
        IAMOAuthBearerLoginCallbackHandler loginCallbackHandler = new IAMOAuthBearerLoginCallbackHandler();
        String debug2 = IAMOAuthBearerLoginCallbackHandler.debugClassString(loginCallbackHandler.getClass());
        assertTrue(debug2.contains("software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandler"));
    }

    private OAuthBearerToken getTestToken(final String tokenValue) {
        return new IAMOAuthBearerToken(tokenValue, TimeUnit.MINUTES.toSeconds(15));
    }

    private void assertTokenValidity(OAuthBearerToken token, String region, String accessKey, String sessionToken) throws URISyntaxException, ParseException {
        Assertions.assertNotNull(token);
        String tokenValue = token.value();
        Assertions.assertNotNull(tokenValue);
        Assertions.assertEquals("kafka-cluster", token.principalName());
        Assertions.assertEquals(Collections.emptySet(), token.scope());
        Assertions.assertTrue(token.startTimeMs() <= System.currentTimeMillis());
        byte[] tokenBytes = tokenValue.getBytes(StandardCharsets.UTF_8);
        String decodedPresignedUrl = new String(Base64.getUrlDecoder()
                                                        .decode(tokenBytes), StandardCharsets.UTF_8);
        final URI uri = new URI(decodedPresignedUrl);
        Assertions.assertEquals(String.format("kafka.%s.amazonaws.com", region), uri.getHost());
        Assertions.assertEquals("https", uri.getScheme());

        List<NameValuePair> params = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);
        Map<String, String> paramMap = params.stream()
                .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));
        Assertions.assertEquals("kafka-cluster:Connect", paramMap.get("Action"));
        Assertions.assertEquals(SignerConstant.AWS4_SIGNING_ALGORITHM, paramMap.get(SignerConstant.X_AMZ_ALGORITHM));
        final Integer expirySeconds = Integer.parseInt(paramMap.get(SignerConstant.X_AMZ_EXPIRES));
        Assertions.assertTrue(expirySeconds <= 900);
        Assertions.assertTrue(token.lifetimeMs() <= System.currentTimeMillis() + Integer.parseInt(paramMap.get(SignerConstant.X_AMZ_EXPIRES)) * 1000);
        Assertions.assertEquals(sessionToken, paramMap.get(SignerConstant.X_AMZ_SECURITY_TOKEN));
        Assertions.assertEquals("host", paramMap.get(SignerConstant.X_AMZ_SIGNED_HEADERS));
        String credential = paramMap.get(SignerConstant.X_AMZ_CREDENTIAL);
        Assertions.assertNotNull(credential);
        String[] credentialArray = credential.split("/");
        Assertions.assertEquals(5, credentialArray.length);
        Assertions.assertEquals(accessKey, credentialArray[0]);
        Assertions.assertEquals("kafka-cluster", credentialArray[3]);
        Assertions.assertEquals(SignerConstant.AWS4_TERMINATOR, credentialArray[4]);
        DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
        final LocalDateTime signedDate = LocalDateTime.parse(paramMap.get(SignerConstant.X_AMZ_DATE), dateFormat);
        long signedDateEpochMillis = signedDate.toInstant(ZoneOffset.UTC)
                .toEpochMilli();
        Assertions.assertTrue(signedDateEpochMillis <= Instant.now()
                .toEpochMilli());
        Assertions.assertEquals(signedDateEpochMillis, token.startTimeMs());
        Assertions.assertEquals(signedDateEpochMillis + expirySeconds * 1000, token.lifetimeMs());
        String userAgent = paramMap.get("User-Agent");
        Assertions.assertNotNull(userAgent);
        Assertions.assertTrue(userAgent.startsWith("aws-msk-iam-auth"));
    }

    private void cleanUp() {
        System.clearProperty("aws.accessKeyId");
        System.clearProperty("aws.secretKey");
        System.clearProperty("aws.sessionToken");
        System.clearProperty("aws.profile");
        System.clearProperty("aws.region");
    }
}
