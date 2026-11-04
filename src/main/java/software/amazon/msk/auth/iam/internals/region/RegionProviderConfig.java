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
package software.amazon.msk.auth.iam.internals.region;

import java.util.Hashtable;
import java.util.Map;

import javax.naming.directory.DirContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.msk.auth.iam.internals.utils.RegionUtils;

/**
 * Shared configuration parsing, JNDI DNS environment construction and region-id validation for the
 * DNS-backed region providers, so the providers agree on parameter names, defaults and clamping.
 */
final class RegionProviderConfig {
    private static final Logger log = LoggerFactory.getLogger(RegionProviderConfig.class);

    static final String HOST_KEY = "host";
    static final String REFRESH_SECONDS_KEY = "refresh.seconds";
    static final String DNS_TIMEOUT_MS_KEY = "dns.timeout.ms";
    static final String DNS_RETRIES_KEY = "dns.retries";

    static final long DEFAULT_REFRESH_SECONDS = 60;

    // These mirror the JDK's own JNDI DNS defaults exactly -- see DEFAULT_INIT_TIMEOUT and
    // DEFAULT_RETRIES in com.sun.jndi.dns.DnsContext. Setting them explicitly to the same values
    // leaves resolution behaviour identical to not setting them at all, which matters because
    // Route53RegionProvider shipped without them: a lower retry count here would silently shorten
    // the DNS timeout for every existing deployment of that provider. The parameters exist so an
    // operator can *tighten* the bound, not so this library can tighten it on their behalf.
    // DnsClient retries with a doubling timeout (pktTimeout = timeout * (1 << retry)), so these
    // defaults allow 1s + 2s + 4s + 8s = 15s per server before a lookup is abandoned.
    static final long DEFAULT_DNS_TIMEOUT_MS = 1000;
    static final int DEFAULT_DNS_RETRIES = 4;

    private RegionProviderConfig() {
    }

    /**
     * Reads a long parameter, falling back to {@code defaultValue} when absent, blank or
     * unparseable, and clamping the result up to {@code minimum}.
     */
    static long parseLong(Map<String, String> config, String key, long defaultValue, long minimum) {
        String value = config != null ? config.get(key) : null;
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Math.max(minimum, Long.parseLong(value.trim()));
        } catch (NumberFormatException e) {
            log.warn("Invalid value for {}: '{}'. Using default {}.", key, value, defaultValue);
            return defaultValue;
        }
    }

    /**
     * Reads an int parameter, clamping into {@code [minimum, Integer.MAX_VALUE]}.
     *
     * <p>The clamp is applied in {@code long} arithmetic before the narrowing conversion. Parsing
     * as a long and casting afterwards would let a value above {@link Integer#MAX_VALUE} wrap to a
     * small or negative number, silently defeating the minimum: a {@code max.hops} of 4294967296
     * would become 0 and skip the work the parameter is meant to bound.</p>
     */
    static int parseBoundedInt(Map<String, String> config, String key, int defaultValue, int minimum) {
        long parsed = parseLong(config, key, defaultValue, minimum);
        return (int) Math.min(Integer.MAX_VALUE, parsed);
    }

    /**
     * Builds the JNDI environment for a DNS lookup against the JDK's built-in DNS provider.
     *
     * <p>The timeout and retry count bound how long an unresponsive resolver can stall
     * authentication. The defaults reproduce the JDK's own values, so a caller that configures
     * neither parameter sees the resolution behaviour it saw before these parameters existed. A
     * provider issuing one lookup per DNS indirection multiplies the worst case, so an operator
     * who cares about authentication latency should lower them deliberately.</p>
     */
    static Hashtable<String, String> dnsEnv(long timeoutMs, int retries) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(DirContext.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put("com.sun.jndi.dns.timeout.initial", Long.toString(timeoutMs));
        env.put("com.sun.jndi.dns.timeout.retries", Integer.toString(retries));
        return env;
    }

    /**
     * Validates an operator-supplied region id (for example the value of a region TXT record) and
     * converts it to a {@link Region}.
     *
     * <p>{@link Region#of} mints a Region for any string whatsoever, so an unvalidated value
     * becomes a signing region that no endpoint exists for and authentication fails with nothing
     * pointing at the real cause. This accepts a region id this SDK knows, and also one that merely
     * matches a partition's region naming pattern so that regions launched after this release still
     * resolve, but rejects a value that is not shaped like a region at all.</p>
     *
     * @param regionId the region id to validate.
     * @param source   description of where the value came from, used in the failure message.
     * @return the validated region.
     * @throws SdkClientException if the value is not a plausible region id.
     */
    static Region validateRegionId(String regionId, String source) {
        return RegionUtils.regionFromLabel(regionId)
                .orElseThrow(() -> SdkClientException.create(
                        "'" + regionId + "' from " + source + " is not a valid AWS region id"));
    }
}
