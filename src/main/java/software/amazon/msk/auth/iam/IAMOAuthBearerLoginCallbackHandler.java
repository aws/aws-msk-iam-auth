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
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lombok.NonNull;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.AwsRegionProvider;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.msk.auth.iam.internals.AWS4SignedPayloadGenerator;
import software.amazon.msk.auth.iam.internals.AuthenticationRequestParams;
import software.amazon.msk.auth.iam.internals.MSKCredentialProvider;
import software.amazon.msk.auth.iam.internals.UserAgentUtils;

/**
 * This login callback handler is used to extract base64 encoded signed url as an auth token.
 * The credentials are based on JaasConfig options passed to {@link OAuthBearerLoginModule}.
 * If config options are provided the {@link MSKCredentialProvider} is used.
 * If no config options are provided it uses the DefaultAWSCredentialsProviderChain.
 */
public class IAMOAuthBearerLoginCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(IAMOAuthBearerLoginCallbackHandler.class);
    private static final String USER_AGENT_KEY = "User-Agent";

    private final AWS4SignedPayloadGenerator aws4Signer = new AWS4SignedPayloadGenerator();

    private AwsCredentialsProvider credentialsProvider;
    private AwsRegionProvider awsRegionProvider;
    private boolean configured = false;

    /**
     * Return true if this instance has been configured, otherwise false.
     */
    public boolean configured() {
        return configured;
    }

    @Override
    public void configure(Map<String, ?> configs,
                          @NonNull String saslMechanism,
                          @NonNull List<AppConfigurationEntry> jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism)) {
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        }

        final Optional<AppConfigurationEntry> configEntry = jaasConfigEntries.stream()
                .filter(j -> OAuthBearerLoginModule.class.getCanonicalName()
                        .equals(j.getLoginModuleName()))
                .findFirst();

        credentialsProvider = configEntry.map(c -> (AwsCredentialsProvider) new MSKCredentialProvider(c.getOptions()))
                .orElse(DefaultCredentialsProvider.create());

        awsRegionProvider = new DefaultAwsRegionProviderChain();
        configured = true;
    }

    @Override
    public void close() {
        try {
            if (credentialsProvider instanceof AutoCloseable) {
                ((AutoCloseable) credentialsProvider).close();
            }
        } catch (Exception e) {
            LOGGER.warn("Error closing provider", e);
        }
    }

    @Override
    public void handle(@NonNull Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (!configured()) {
            throw new IllegalStateException("Callback handler not configured");
        }
        for (Callback callback : callbacks) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Type information for callback: " + debugClassString(callback.getClass()) + " from "
                                  + debugClassString(this.getClass()));
            }
            if (callback instanceof OAuthBearerTokenCallback) {
                try {
                    handleCallback((OAuthBearerTokenCallback) callback);
                } catch (ParseException | URISyntaxException e) {
                    throw new MalformedURLException(e.getMessage());
                }
            } else {
                String message = "Unsupported callback type: " + debugClassString(callback.getClass()) + " from "
                        + debugClassString(this.getClass());
                throw new UnsupportedCallbackException(callback, message);
            }
        }
    }

    private void handleCallback(OAuthBearerTokenCallback callback) throws IOException, URISyntaxException, ParseException {
        if (callback.token() != null) {
            throw new IllegalArgumentException("Callback had a token already");
        }
        AwsCredentials awsCredentials = credentialsProvider.resolveCredentials();

        // Generate token value i.e. Base64 encoded pre-signed URL string
        String tokenValue = generateTokenValue(awsCredentials, getCurrentRegion());
        // Set OAuth token
        callback.token(getOAuthBearerToken(tokenValue));
    }

    /**
     * Generates base64 encoded signed url based on IAM credentials provided
     *
     * @param awsCredentials aws credentials object
     * @param region aws region
     * @return a base64 encoded token string
     */
    private String generateTokenValue(@NonNull final AwsCredentials awsCredentials, @NonNull final Region region) {
        final String userAgentValue = UserAgentUtils.getUserAgentValue();
        final AuthenticationRequestParams authenticationRequestParams = AuthenticationRequestParams
                .create(getHostName(region), awsCredentials, userAgentValue);

        final SdkHttpFullRequest.Builder requestBuilder = aws4Signer.presignRequest(authenticationRequestParams).toBuilder();
        requestBuilder.appendRawQueryParameter(USER_AGENT_KEY, userAgentValue);
        final SdkHttpFullRequest fullRequest = requestBuilder.build();
        String signedUrl = fullRequest.getUri().toString();
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(signedUrl.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Builds hostname string
     *
     * @param region aws region
     * @return hostname
     */
    private String getHostName(final Region region) {
        return String.format("kafka.%s.amazonaws.com", region.toString());
    }

    /**
     * Gets current aws region from metadata
     *
     * @return aws region object
     * @throws IOException
     */
    private Region getCurrentRegion() throws IOException {
        try {
            return awsRegionProvider.getRegion();
        } catch (SdkClientException exception) {
            throw new IOException("AWS region could not be resolved.");
        }
    }

    /**
     * Constructs OAuthBearerToken object as required by OAuthModule
     *
     * @param token base64 encoded token
     * @return
     */
    private OAuthBearerToken getOAuthBearerToken(final String token) throws URISyntaxException, ParseException {
        return new IAMOAuthBearerToken(token);
    }

    static String debugClassString(Class<?> clazz) {
        return "class: " + clazz.getName() + " classloader: " + clazz.getClassLoader().toString();
    }
}

