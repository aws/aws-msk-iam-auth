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

import java.time.Clock;
import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;

/**
 * A {@link ConfigurableRegionProvider} that resolves the AWS region by performing
 * a DNS TXT record lookup via Route 53, with time-based caching.
 *
 * <p>Configuration parameters (passed via constructor map):</p>
 * <ul>
 *   <li>{@code host} — optional fully-qualified hostname to query for the TXT record.
 *       When provided, this value is used directly as the DNS lookup name.</li>
 *   <li>{@code refresh.seconds} — how often, in seconds, the cached region value
 *       is refreshed via a new DNS lookup. Defaults to 60 (1 minute).
 *       Set to 0 to disable caching and resolve DNS on every call.
 *       Uses lazy evaluation: the cache is only refreshed when an authentication
 *       request needs to be signed, which typically happens during initial
 *       authentication with MSK and subsequent re-authentication to refresh
 *       session tokens. Caching reduces the number of Route 53 DNS calls,
 *       which is especially beneficial when authentication is retried
 *       repeatedly due to failures.
 *       <p>When a refresh fails and a region was previously resolved for the same lookup name, the
 *       last known good region is served rather than failing: falling back to the
 *       {@code DefaultAwsRegionProviderChain} would resolve from the environment, profile file or
 *       IMDS, none of which know about this TXT record, so its answer is very likely the wrong
 *       region. Each stale serve is logged at WARN.</p></li>
 *   <li>{@code dns.timeout.ms} — initial DNS query timeout in milliseconds. Defaults to 1000.</li>
 *   <li>{@code dns.retries} — how many times a DNS query is retried, each retry doubling the
 *       timeout. Defaults to 2. Together with {@code dns.timeout.ms} this bounds how long an
 *       unresponsive resolver can stall authentication.</li>
 * </ul>
 *
 * <p>The TXT value is validated as a region id before use, so a typo fails with a message naming
 * the record instead of producing a signing region that no endpoint exists for.</p>
 *
 * <p>When no {@code host} is configured, the {@link #getRegion(String)} method
 * constructs the lookup name by prefixing the supplied host with {@code "region."}
 * (e.g. {@code "region.broker.example.com"}).</p>
 *
 * <p>The TXT record value is expected to contain a valid AWS region id
 * (e.g. {@code "us-east-1"}).</p>
 */
public class Route53RegionProvider implements ConfigurableRegionProvider {
    private static final Logger log = LoggerFactory.getLogger(Route53RegionProvider.class);
    private static final String REGION_PREFIX = "region.";

    private final String host;
    private final long dnsTimeoutMs;
    private final int dnsRetries;
    private final CachedRegionResolver cache;

    public Route53RegionProvider(Map<String, String> config) {
        this(config, Clock.systemUTC());
    }

    // Visible for testing
    Route53RegionProvider(Map<String, String> config, Clock clock) {
        this.host = config != null ? config.get(RegionProviderConfig.HOST_KEY) : null;
        this.dnsTimeoutMs = RegionProviderConfig.parseLong(config,
                RegionProviderConfig.DNS_TIMEOUT_MS_KEY, RegionProviderConfig.DEFAULT_DNS_TIMEOUT_MS, 1);
        this.dnsRetries = RegionProviderConfig.parseBoundedInt(config,
                RegionProviderConfig.DNS_RETRIES_KEY, RegionProviderConfig.DEFAULT_DNS_RETRIES, 0);
        long refreshSeconds = RegionProviderConfig.parseLong(config,
                RegionProviderConfig.REFRESH_SECONDS_KEY, RegionProviderConfig.DEFAULT_REFRESH_SECONDS, 0);
        this.cache = new CachedRegionResolver(refreshSeconds, clock);
        if (log.isDebugEnabled()) {
            log.debug("Route53RegionProvider initialized with host={}, refresh.seconds={}, "
                            + "dns.timeout.ms={}, dns.retries={}",
                    this.host, refreshSeconds, this.dnsTimeoutMs, this.dnsRetries);
        }
    }

    @Override
    public Region getRegion() {
        return getRegion(null);
    }

    @Override
    public Region getRegion(String host) {
        String lookupHost = this.host != null ? this.host : buildLookupHost(host);
        if (lookupHost == null || lookupHost.isBlank()) {
            throw SdkClientException.create(
                    "Cannot resolve region: no host configured and no host parameter provided");
        }

        return cache.resolve(lookupHost, () -> {
            if (log.isDebugEnabled()) {
                log.debug("Resolving region via TXT record for host: {}", lookupHost);
            }
            String regionId = resolveTxtRecord(lookupHost);
            return RegionProviderConfig.validateRegionId(regionId, "the TXT record at " + lookupHost);
        });
    }

    private String buildLookupHost(String host) {
        if (host == null || host.isBlank()) {
            return null;
        }
        return REGION_PREFIX + host;
    }


    /**
     * Resolves a DNS TXT record for the given hostname using JNDI with the
     * {@code com.sun.jndi.dns.DnsContextFactory} built-in JDK DNS provider.
     *
     * <p>Only the first TXT record value is used. This is intentional — the
     * TXT record is expected to be a dedicated, environment-controlled record
     * whose sole value is the active AWS region id. Surrounding quotes are
     * stripped from the returned value.</p>
     *
     * @param lookupHost the fully-qualified hostname to query
     * @return the TXT record value (unquoted and trimmed)
     * @throws SdkClientException if no TXT record is found or the DNS lookup fails
     */
    String resolveTxtRecord(String lookupHost) {
        try {
            DirContext ctx = new InitialDirContext(
                    RegionProviderConfig.dnsEnv(dnsTimeoutMs, dnsRetries));
            try {
                Attributes attrs = ctx.getAttributes(lookupHost, new String[]{"TXT"});
                Attribute txtAttr = attrs.get("TXT");
                if (txtAttr == null || txtAttr.size() == 0) {
                    throw SdkClientException.create(
                            "No TXT record found for host: " + lookupHost);
                }
                NamingEnumeration<?> values = txtAttr.getAll();
                String value = (String) values.next();
                return value.replace("\"", "").trim();
            } finally {
                ctx.close();
            }
        } catch (NamingException e) {
            throw SdkClientException.create(
                    "Failed to resolve TXT record for host: " + lookupHost, e);
        }
    }

}
