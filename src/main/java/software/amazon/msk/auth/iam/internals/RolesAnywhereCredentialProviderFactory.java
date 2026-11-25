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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.SdkHttpService;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.utils.AttributeMap;
import software.amazon.rolesanywhere.plugin.RolesAnywhereCredentialsProvider;
import software.amazon.rolesanywhere.plugin.X509IdentityProvider;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Factory that builds an {@link AwsCredentialsProvider} backed by
 * {@link RolesAnywhereCredentialsProvider} from JAAS configuration options,
 * enabling in-process IAM Roles Anywhere authentication without requiring
 * the external {@code aws_signing_helper} binary.
 */
class RolesAnywhereCredentialProviderFactory {
    private static final Logger log = LoggerFactory.getLogger(RolesAnywhereCredentialProviderFactory.class);

    static final String AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN = "awsRolesAnywhereTrustAnchorArn";
    static final String AWS_ROLES_ANYWHERE_PROFILE_ARN = "awsRolesAnywhereProfileArn";
    static final String AWS_ROLES_ANYWHERE_ROLE_ARN = "awsRolesAnywhereRoleArn";
    static final String AWS_ROLES_ANYWHERE_CERTIFICATE = "awsRolesAnywhereCertificate";
    static final String AWS_ROLES_ANYWHERE_PRIVATE_KEY = "awsRolesAnywherePrivateKey";
    static final String AWS_ROLES_ANYWHERE_PRIVATE_KEY_ALGORITHM = "awsRolesAnywherePrivateKeyAlgorithm";
    static final String AWS_ROLES_ANYWHERE_PRIVATE_KEY_PASSWORD = "awsRolesAnywherePrivateKeyPassword";
    static final String AWS_ROLES_ANYWHERE_CERTIFICATE_CHAIN = "awsRolesAnywhereCertificateChain";
    static final String AWS_ROLES_ANYWHERE_REGION = "awsRolesAnywhereRegion";
    static final String AWS_ROLES_ANYWHERE_ROLE_SESSION_NAME = "awsRolesAnywhereRoleSessionName";
    static final String AWS_ROLES_ANYWHERE_DURATION_SECONDS = "awsRolesAnywhereDurationSeconds";
    static final String AWS_ROLES_ANYWHERE_ENDPOINT = "awsRolesAnywhereEndpoint";
    static final String AWS_ROLES_ANYWHERE_DUAL_STACK_ENABLED = "awsRolesAnywhereDualStackEnabled";
    static final String AWS_ROLES_ANYWHERE_STALE_TIME_SECONDS = "awsRolesAnywhereStaleTimeSeconds";
    static final String AWS_ROLES_ANYWHERE_MIN_REFRESH_INTERVAL_SECONDS = "awsRolesAnywhereMinRefreshIntervalSeconds";

    private static final String DEFAULT_KEY_ALGORITHM = "RSA";
    private static final Duration DEFAULT_CONNECTION_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_SOCKET_TIMEOUT = Duration.ofSeconds(30);

    private static final Set<String> ALL_OPTION_KEYS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN,
            AWS_ROLES_ANYWHERE_PROFILE_ARN,
            AWS_ROLES_ANYWHERE_ROLE_ARN,
            AWS_ROLES_ANYWHERE_CERTIFICATE,
            AWS_ROLES_ANYWHERE_PRIVATE_KEY,
            AWS_ROLES_ANYWHERE_PRIVATE_KEY_ALGORITHM,
            AWS_ROLES_ANYWHERE_PRIVATE_KEY_PASSWORD,
            AWS_ROLES_ANYWHERE_CERTIFICATE_CHAIN,
            AWS_ROLES_ANYWHERE_REGION,
            AWS_ROLES_ANYWHERE_ROLE_SESSION_NAME,
            AWS_ROLES_ANYWHERE_DURATION_SECONDS,
            AWS_ROLES_ANYWHERE_ENDPOINT,
            AWS_ROLES_ANYWHERE_DUAL_STACK_ENABLED,
            AWS_ROLES_ANYWHERE_STALE_TIME_SECONDS,
            AWS_ROLES_ANYWHERE_MIN_REFRESH_INTERVAL_SECONDS
    )));

    private RolesAnywhereCredentialProviderFactory() {
    }

    /**
     * Returns {@code true} if any IAM Roles Anywhere JAAS option is present in {@code optionsMap}.
     */
    static boolean isConfigured(Map<String, ?> optionsMap) {
        if (optionsMap == null || optionsMap.isEmpty()) {
            return false;
        }
        for (String key : ALL_OPTION_KEYS) {
            if (optionsMap.get(key) != null) {
                return true;
            }
        }
        return false;
    }

    /**
     * Creates a managed {@link AwsCredentialsProvider} backed by IAM Roles Anywhere.
     * The returned provider implements {@link AutoCloseable} and closes both the
     * underlying {@link RolesAnywhereCredentialsProvider} and its {@link SdkHttpClient}.
     */
    static AwsCredentialsProvider create(Map<String, ?> optionsMap, boolean shouldUseFips) {
        SdkHttpClient httpClient = createDefaultHttpClient();
        try {
            return create(optionsMap, shouldUseFips, httpClient);
        } catch (RuntimeException e) {
            closeQuietly(httpClient);
            throw e;
        }
    }

    static AwsCredentialsProvider create(Map<String, ?> optionsMap,
                                         boolean shouldUseFips,
                                         SdkHttpClient httpClient) {
        List<String> missing = new ArrayList<>();
        String trustAnchorArn = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN);
        String profileArn = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_PROFILE_ARN);
        String roleArn = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_ROLE_ARN);
        String certificatePathStr = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_CERTIFICATE);
        String privateKeyPathStr = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_PRIVATE_KEY);

        if (trustAnchorArn == null) {
            missing.add(AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN);
        }
        if (profileArn == null) {
            missing.add(AWS_ROLES_ANYWHERE_PROFILE_ARN);
        }
        if (roleArn == null) {
            missing.add(AWS_ROLES_ANYWHERE_ROLE_ARN);
        }
        if (certificatePathStr == null) {
            missing.add(AWS_ROLES_ANYWHERE_CERTIFICATE);
        }
        if (privateKeyPathStr == null) {
            missing.add(AWS_ROLES_ANYWHERE_PRIVATE_KEY);
        }
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException(
                    "Missing required IAM Roles Anywhere JAAS option(s): " + String.join(", ", missing));
        }

        String keyAlgorithm = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_PRIVATE_KEY_ALGORITHM);
        if (keyAlgorithm == null) {
            keyAlgorithm = DEFAULT_KEY_ALGORITHM;
        }

        String certificateChainPathStr = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_CERTIFICATE_CHAIN);
        Path certificatePath = Paths.get(certificatePathStr);
        Path privateKeyPath = Paths.get(privateKeyPathStr);
        Path certificateChainPath = certificateChainPathStr != null ? Paths.get(certificateChainPathStr) : null;

        String rawPassword = getRawStringOption(optionsMap, AWS_ROLES_ANYWHERE_PRIVATE_KEY_PASSWORD);
        char[] password = rawPassword != null ? rawPassword.toCharArray() : null;

        X509IdentityProvider identityProvider = X509IdentityProvider.fromFiles(
                certificatePath,
                privateKeyPath,
                keyAlgorithm,
                certificateChainPath,
                password);

        RolesAnywhereCredentialsProvider.Builder builder = RolesAnywhereCredentialsProvider.builder()
                .identityProvider(identityProvider)
                .trustAnchorArn(trustAnchorArn)
                .profileArn(profileArn)
                .roleArn(roleArn)
                .httpClient(httpClient);

        String region = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_REGION);
        if (region != null) {
            builder.region(Region.of(region));
        }

        String roleSessionName = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_ROLE_SESSION_NAME);
        if (roleSessionName != null) {
            builder.roleSessionName(roleSessionName);
        }

        String durationSeconds = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_DURATION_SECONDS);
        if (durationSeconds != null) {
            builder.durationSeconds(parseIntOption(AWS_ROLES_ANYWHERE_DURATION_SECONDS, durationSeconds));
        }

        String endpoint = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_ENDPOINT);
        if (endpoint != null) {
            builder.endpoint(parseUriOption(AWS_ROLES_ANYWHERE_ENDPOINT, endpoint));
        }

        if (shouldUseFips) {
            builder.fipsEnabled(true);
        }

        String dualStack = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_DUAL_STACK_ENABLED);
        if (dualStack != null) {
            builder.dualStackEnabled(parseBooleanOption(AWS_ROLES_ANYWHERE_DUAL_STACK_ENABLED, dualStack));
        }

        String staleTimeSeconds = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_STALE_TIME_SECONDS);
        if (staleTimeSeconds != null) {
            builder.staleTime(Duration.ofSeconds(
                    parseLongOption(AWS_ROLES_ANYWHERE_STALE_TIME_SECONDS, staleTimeSeconds)));
        }

        String minRefreshIntervalSeconds = getTrimmedOption(optionsMap, AWS_ROLES_ANYWHERE_MIN_REFRESH_INTERVAL_SECONDS);
        if (minRefreshIntervalSeconds != null) {
            builder.minRefreshInterval(Duration.ofSeconds(
                    parseLongOption(AWS_ROLES_ANYWHERE_MIN_REFRESH_INTERVAL_SECONDS, minRefreshIntervalSeconds)));
        }

        if (log.isDebugEnabled()) {
            log.debug("Configuring IAM Roles Anywhere credential provider for roleArn={}, profileArn={}, trustAnchorArn={}",
                    roleArn, profileArn, trustAnchorArn);
        }

        RolesAnywhereCredentialsProvider provider = builder.build();
        return new ManagedRolesAnywhereCredentialsProvider(provider, httpClient);
    }

    /**
     * Builds a synchronous {@link SdkHttpClient} via the AWS SDK {@link SdkHttpService} SPI
     * (resolving {@code apache5-client} by default in this library) so that
     * {@link RolesAnywhereCredentialsProvider} does not fall back to the excluded
     * {@code apache-client} (HttpClient 4.x) implementation.
     */
    static SdkHttpClient createDefaultHttpClient() {
        ServiceLoader<SdkHttpService> services = ServiceLoader.load(
                SdkHttpService.class, RolesAnywhereCredentialProviderFactory.class.getClassLoader());
        SdkHttpService httpService = services.findFirst().orElse(null);
        if (httpService == null) {
            httpService = ServiceLoader.load(SdkHttpService.class).findFirst().orElseThrow(() ->
                    SdkClientException.create(
                            "No AWS SDK synchronous SdkHttpService implementation found on the classpath "
                                    + "(expected software.amazon.awssdk:apache5-client or another SdkHttpService)."));
        }
        AttributeMap defaults = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.CONNECTION_TIMEOUT, DEFAULT_CONNECTION_TIMEOUT)
                .put(SdkHttpConfigurationOption.READ_TIMEOUT, DEFAULT_SOCKET_TIMEOUT)
                .build();
        return httpService.createHttpClientBuilder().buildWithDefaults(defaults);
    }

    private static String getTrimmedOption(Map<String, ?> optionsMap, String key) {
        Object value = optionsMap.get(key);
        if (value == null) {
            return null;
        }
        String trimmed = value.toString().trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String getRawStringOption(Map<String, ?> optionsMap, String key) {
        Object value = optionsMap.get(key);
        return value != null ? value.toString() : null;
    }

    private static int parseIntOption(String key, String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid integer value for JAAS option " + key + ": '" + value + "'", e);
        }
    }

    private static long parseLongOption(String key, String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid long value for JAAS option " + key + ": '" + value + "'", e);
        }
    }

    private static boolean parseBooleanOption(String key, String value) {
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("false".equalsIgnoreCase(value)) {
            return false;
        }
        throw new IllegalArgumentException(
                "Invalid boolean value for JAAS option " + key + ": '" + value + "' (expected 'true' or 'false')");
    }

    private static URI parseUriOption(String key, String value) {
        try {
            return URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Invalid URI value for JAAS option " + key + ": '" + value + "'", e);
        }
    }

    private static void closeQuietly(SdkHttpClient httpClient) {
        if (httpClient != null) {
            try {
                httpClient.close();
            } catch (Exception e) {
                log.warn("Error closing Roles Anywhere HTTP client", e);
            }
        }
    }

    /**
     * Wraps a {@link RolesAnywhereCredentialsProvider} together with the {@link SdkHttpClient}
     * created for it, ensuring both are closed when {@link MSKCredentialProvider#close()} runs.
     * {@link RolesAnywhereCredentialsProvider#close()} intentionally does not close an externally
     * supplied {@link SdkHttpClient}.
     */
    static final class ManagedRolesAnywhereCredentialsProvider implements AwsCredentialsProvider, AutoCloseable {
        private final AwsCredentialsProvider delegate;
        private final SdkHttpClient httpClient;

        ManagedRolesAnywhereCredentialsProvider(AwsCredentialsProvider delegate, SdkHttpClient httpClient) {
            this.delegate = delegate;
            this.httpClient = httpClient;
        }

        @Override
        public AwsCredentials resolveCredentials() {
            return delegate.resolveCredentials();
        }

        @Override
        public CompletableFuture<? extends AwsCredentialsIdentity> resolveIdentity() {
            return delegate.resolveIdentity();
        }

        @Override
        public void close() {
            try {
                if (delegate instanceof AutoCloseable) {
                    ((AutoCloseable) delegate).close();
                }
            } catch (Exception e) {
                log.warn("Error closing RolesAnywhereCredentialsProvider", e);
            } finally {
                closeQuietly(httpClient);
            }
        }
    }
}
