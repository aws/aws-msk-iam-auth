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

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import software.amazon.awssdk.http.auth.aws.signer.SignerConstant;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.msk.auth.iam.internals.utils.URIUtils;

/**
 * Implements the contract provided by OAuthBearerToken interface
 */
public class IAMOAuthBearerToken implements OAuthBearerToken {
    private static final String SIGNING_NAME = "kafka-cluster";

    private final String value;
    private final long lifetimeMs;
    private final long startTimeMs;

    // Used for testing
    IAMOAuthBearerToken(String token, long lifeTimeSeconds) {
        this.value = token;
        this.startTimeMs = System.currentTimeMillis();
        this.lifetimeMs = this.startTimeMs + (lifeTimeSeconds * 1000);
    }

    public IAMOAuthBearerToken(String token) throws URISyntaxException {
        if(StringUtils.isEmpty(token)) {
            throw new IllegalArgumentException("Token can not be empty");
        }
        this.value = token;
        byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
        byte[] decodedBytes = Base64.getUrlDecoder().decode(tokenBytes);
        final String decodedPresignedUrl = new String(decodedBytes, StandardCharsets.UTF_8);
        final URI uri = new URI(decodedPresignedUrl);

        Map<String, List<String>> params = URIUtils.parseQueryParams(uri);
        int lifeTimeSeconds = Integer.parseInt(params.get(SignerConstant.X_AMZ_EXPIRES).get(0));
        final DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
        final LocalDateTime signedDate = LocalDateTime.parse(params.get(SignerConstant.X_AMZ_DATE).get(0), dateFormat);
        this.startTimeMs = signedDate.toInstant(ZoneOffset.UTC).toEpochMilli();
        this.lifetimeMs = this.startTimeMs + (lifeTimeSeconds * 1000L);
    }

    @Override
    public String value() {
        return this.value;
    }

    @Override
    public Set<String> scope() {
        return Collections.emptySet();
    }

    @Override
    public long lifetimeMs() {
        return this.lifetimeMs;
    }

    @Override
    public String principalName() {
        return SIGNING_NAME;
    }

    @Override
    public Long startTimeMs() {
        return this.startTimeMs;
    }
}
