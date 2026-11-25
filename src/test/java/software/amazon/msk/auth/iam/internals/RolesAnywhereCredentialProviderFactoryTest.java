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
package software.amazon.msk.auth.iam.internals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RolesAnywhereCredentialProviderFactoryTest {
    private static final String TRUST_ANCHOR_ARN =
            "arn:aws:rolesanywhere:us-west-2:123456789012:trust-anchor/12345678-1234-1234-1234-123456789012";
    private static final String PROFILE_ARN =
            "arn:aws:rolesanywhere:us-west-2:123456789012:profile/12345678-1234-1234-1234-123456789012";
    private static final String ROLE_ARN =
            "arn:aws:iam::123456789012:role/msk_client_role";

    @Test
    public void testIsConfiguredFalseWhenNoRolesAnywhereOptions() {
        assertFalse(RolesAnywhereCredentialProviderFactory.isConfigured(null));
        assertFalse(RolesAnywhereCredentialProviderFactory.isConfigured(Collections.emptyMap()));

        Map<String, String> otherOptions = new HashMap<>();
        otherOptions.put("awsProfileName", "my-profile");
        otherOptions.put("awsRoleArn", ROLE_ARN);
        assertFalse(RolesAnywhereCredentialProviderFactory.isConfigured(otherOptions));
    }

    @Test
    public void testIsConfiguredTrueWhenAnyRolesAnywhereOptionPresent() {
        Map<String, String> partial = new HashMap<>();
        partial.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN, TRUST_ANCHOR_ARN);
        assertTrue(RolesAnywhereCredentialProviderFactory.isConfigured(partial));

        Map<String, String> optionalOnly = new HashMap<>();
        optionalOnly.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_REGION, "us-west-2");
        assertTrue(RolesAnywhereCredentialProviderFactory.isConfigured(optionalOnly));
    }

    @Test
    public void testMissingRequiredOptionsThrowsActionableException() {
        Map<String, String> partial = new HashMap<>();
        partial.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN, TRUST_ANCHOR_ARN);
        partial.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PROFILE_ARN, "   ");

        SdkHttpClient mockHttpClient = Mockito.mock(SdkHttpClient.class);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialProviderFactory.create(partial, false, mockHttpClient));

        assertTrue(ex.getMessage().contains(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PROFILE_ARN));
        assertTrue(ex.getMessage().contains(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_ROLE_ARN));
        assertTrue(ex.getMessage().contains(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_CERTIFICATE));
        assertTrue(ex.getMessage().contains(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PRIVATE_KEY));
    }

    @Test
    public void testCreateWithDefaultHttpClientClosesHttpClientOnValidationFailure() {
        Map<String, String> partial = new HashMap<>();
        partial.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN, TRUST_ANCHOR_ARN);

        assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialProviderFactory.create(partial, false));
    }

    @Test
    public void testInvalidOptionalNumericAndBooleanAndUriOptionsThrowIllegalArgumentException() {
        SdkHttpClient mockHttpClient = Mockito.mock(SdkHttpClient.class);

        Map<String, String> badDuration = validRequiredOptions();
        badDuration.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_DURATION_SECONDS, "not-an-int");
        assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialProviderFactory.create(badDuration, false, mockHttpClient));

        Map<String, String> badStaleTime = validRequiredOptions();
        badStaleTime.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_STALE_TIME_SECONDS, "abc");
        assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialProviderFactory.create(badStaleTime, false, mockHttpClient));

        Map<String, String> badMinRefresh = validRequiredOptions();
        badMinRefresh.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_MIN_REFRESH_INTERVAL_SECONDS, "xyz");
        assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialProviderFactory.create(badMinRefresh, false, mockHttpClient));

        Map<String, String> badDualStack = validRequiredOptions();
        badDualStack.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_DUAL_STACK_ENABLED, "yes");
        assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialProviderFactory.create(badDualStack, false, mockHttpClient));

        Map<String, String> badEndpoint = validRequiredOptions();
        badEndpoint.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_ENDPOINT, "http://[::1");
        assertThrows(IllegalArgumentException.class,
                () -> RolesAnywhereCredentialProviderFactory.create(badEndpoint, false, mockHttpClient));
    }

    @Test
    public void testCreateWithAllOptionsAndDefaultSpiHttpClient() throws Exception {
        Map<String, String> options = validRequiredOptions();
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PRIVATE_KEY_ALGORITHM, "RSA");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PRIVATE_KEY_PASSWORD, "secret");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_CERTIFICATE_CHAIN, "/tmp/chain.pem");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_REGION, "us-west-2");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_ROLE_SESSION_NAME, "msk-session");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_DURATION_SECONDS, "1800");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_ENDPOINT,
                "https://rolesanywhere.us-west-2.amazonaws.com");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_DUAL_STACK_ENABLED, "false");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_STALE_TIME_SECONDS, "120");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_MIN_REFRESH_INTERVAL_SECONDS, "60");

        AwsCredentialsProvider provider = RolesAnywhereCredentialProviderFactory.create(options, true);
        assertNotNull(provider);
        assertTrue(provider instanceof AutoCloseable);
        ((AutoCloseable) provider).close();
    }

    @Test
    public void testManagedProviderDelegatesAndClosesBothDelegateAndHttpClient() throws Exception {
        AwsCredentialsProvider delegate = Mockito.mock(
                AwsCredentialsProvider.class, Mockito.withSettings().extraInterfaces(AutoCloseable.class));
        SdkHttpClient httpClient = Mockito.mock(SdkHttpClient.class);

        AwsSessionCredentials expected = AwsSessionCredentials.create("AKIA_TEST", "SECRET_TEST", "TOKEN_TEST");
        when(delegate.resolveCredentials()).thenReturn(expected);
        when(delegate.resolveIdentity()).thenAnswer(i -> CompletableFuture.completedFuture(expected));

        RolesAnywhereCredentialProviderFactory.ManagedRolesAnywhereCredentialsProvider managed =
                new RolesAnywhereCredentialProviderFactory.ManagedRolesAnywhereCredentialsProvider(delegate, httpClient);

        assertEquals(expected, managed.resolveCredentials());
        AwsCredentialsIdentity identity = managed.resolveIdentity().get();
        assertEquals(expected, identity);

        managed.close();
        verify((AutoCloseable) delegate, times(1)).close();
        verify(httpClient, times(1)).close();
    }

    @Test
    public void testManagedProviderClosesHttpClientEvenIfDelegateCloseThrows() throws Exception {
        AwsCredentialsProvider delegate = Mockito.mock(
                AwsCredentialsProvider.class, Mockito.withSettings().extraInterfaces(AutoCloseable.class));
        SdkHttpClient httpClient = Mockito.mock(SdkHttpClient.class);
        doThrow(new RuntimeException("boom")).when((AutoCloseable) delegate).close();

        RolesAnywhereCredentialProviderFactory.ManagedRolesAnywhereCredentialsProvider managed =
                new RolesAnywhereCredentialProviderFactory.ManagedRolesAnywhereCredentialsProvider(delegate, httpClient);

        managed.close();
        verify((AutoCloseable) delegate, times(1)).close();
        verify(httpClient, times(1)).close();
    }

    @Test
    public void testEndToEndResolveCredentialsWithPemFilesAndMockHttpClient(@TempDir Path tempDir) throws Exception {
        Path certPath = tempDir.resolve("client-cert.pem");
        Path keyPath = tempDir.resolve("client-key.pem");
        generateSelfSignedRsaPem(tempDir, certPath, keyPath);

        String expiration = Instant.now().plus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS).toString();
        String responseJson = "{"
                + "\"credentialSet\":[{"
                + "\"credentials\":{"
                + "\"accessKeyId\":\"ASIA_ROLES_ANYWHERE\","
                + "\"secretAccessKey\":\"SECRET_ROLES_ANYWHERE\","
                + "\"sessionToken\":\"TOKEN_ROLES_ANYWHERE\","
                + "\"expiration\":\"" + expiration + "\""
                + "}"
                + "}]"
                + "}";

        SdkHttpClient mockHttpClient = Mockito.mock(SdkHttpClient.class);
        ExecutableHttpRequest executableRequest = Mockito.mock(ExecutableHttpRequest.class);
        when(mockHttpClient.prepareRequest(any(HttpExecuteRequest.class))).thenReturn(executableRequest);
        when(executableRequest.call()).thenReturn(HttpExecuteResponse.builder()
                .response(SdkHttpResponse.builder().statusCode(200).build())
                .responseBody(AbortableInputStream.create(
                        new ByteArrayInputStream(responseJson.getBytes(StandardCharsets.UTF_8))))
                .build());

        Map<String, String> options = new HashMap<>();
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN, TRUST_ANCHOR_ARN);
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PROFILE_ARN, PROFILE_ARN);
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_ROLE_ARN, ROLE_ARN);
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_CERTIFICATE, certPath.toString());
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PRIVATE_KEY, keyPath.toString());
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_ROLE_SESSION_NAME, "msk-test-session");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_DURATION_SECONDS, "3600");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_MIN_REFRESH_INTERVAL_SECONDS, "0");

        AwsCredentialsProvider provider = RolesAnywhereCredentialProviderFactory.create(options, false, mockHttpClient);
        try {
            AwsCredentials credentials = provider.resolveCredentials();
            assertTrue(credentials instanceof AwsSessionCredentials);
            AwsSessionCredentials sessionCreds = (AwsSessionCredentials) credentials;
            assertEquals("ASIA_ROLES_ANYWHERE", sessionCreds.accessKeyId());
            assertEquals("SECRET_ROLES_ANYWHERE", sessionCreds.secretAccessKey());
            assertEquals("TOKEN_ROLES_ANYWHERE", sessionCreds.sessionToken());

            ArgumentCaptor<HttpExecuteRequest> requestCaptor = ArgumentCaptor.forClass(HttpExecuteRequest.class);
            verify(mockHttpClient, times(1)).prepareRequest(requestCaptor.capture());
            HttpExecuteRequest captured = requestCaptor.getValue();
            assertEquals("rolesanywhere.us-west-2.amazonaws.com", captured.httpRequest().host());
            assertTrue(captured.httpRequest().firstMatchingHeader("X-Amz-X509").isPresent());
            assertTrue(captured.httpRequest().firstMatchingHeader("Authorization")
                    .map(h -> h.startsWith("AWS4-X509-RSA-SHA256"))
                    .orElse(false));
        } finally {
            ((AutoCloseable) provider).close();
        }
        verify(mockHttpClient, times(1)).close();
    }

    private Map<String, String> validRequiredOptions() {
        Map<String, String> options = new HashMap<>();
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN, TRUST_ANCHOR_ARN);
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PROFILE_ARN, PROFILE_ARN);
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_ROLE_ARN, ROLE_ARN);
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_CERTIFICATE, "/tmp/cert.pem");
        options.put(RolesAnywhereCredentialProviderFactory.AWS_ROLES_ANYWHERE_PRIVATE_KEY, "/tmp/key.pem");
        return options;
    }

    private static void generateSelfSignedRsaPem(Path tempDir, Path certPath, Path keyPath) throws Exception {
        Path keystorePath = tempDir.resolve("test.p12");
        String keytoolBin = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process process = new ProcessBuilder(
                keytoolBin,
                "-genkeypair",
                "-alias", "test",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-sigalg", "SHA256withRSA",
                "-dname", "CN=msk-roles-anywhere-test",
                "-validity", "2",
                "-keystore", keystorePath.toString(),
                "-storetype", "PKCS12",
                "-storepass", "changeit")
                .redirectErrorStream(true)
                .start();
        int exitCode = process.waitFor();
        assertEquals(0, exitCode, "keytool failed to generate test keypair");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystorePath)) {
            ks.load(in, "changeit".toCharArray());
        }
        Certificate cert = ks.getCertificate("test");
        PrivateKey key = (PrivateKey) ks.getKey("test", "changeit".toCharArray());

        Files.writeString(certPath, toPem("CERTIFICATE", cert.getEncoded()), StandardCharsets.UTF_8);
        Files.writeString(keyPath, toPem("PRIVATE KEY", key.getEncoded()), StandardCharsets.UTF_8);
    }

    private static String toPem(String type, byte[] derBytes) {
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(derBytes);
        return "-----BEGIN " + type + "-----\n" + encoded + "\n-----END " + type + "-----\n";
    }
}
