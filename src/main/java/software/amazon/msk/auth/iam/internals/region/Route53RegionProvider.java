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
import java.time.Instant;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
 *       repeatedly due to failures.</li>
 * </ul>
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
    private static final String HOST_KEY = "host";

    private static final String REFRESH_SECONDS_KEY = "refresh.seconds";
    private static final String REGION_PREFIX = "region.";
    private static final long DEFAULT_REFRESH_SECONDS = 60;

    private final String host;
    private final long refreshSeconds;
    private final Clock clock;
    private final ConcurrentHashMap<String, CachedRegion> cache = new ConcurrentHashMap<>();

    public Route53RegionProvider(Map<String, String> config) {
        this(config, Clock.systemUTC());
    }

    // Visible for testing
    Route53RegionProvider(Map<String, String> config, Clock clock) {
        this.host = config != null ? config.get(HOST_KEY) : null;
        this.refreshSeconds = parseRefreshSeconds(config);
        this.clock = clock;
        if (log.isDebugEnabled()) {
            log.debug("Route53RegionProvider initialized with host={}, refresh.seconds={}",
                    this.host, this.refreshSeconds);
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

        if (refreshSeconds > 0) {
            CachedRegion cached = cache.get(lookupHost);
            if (cached != null && !cached.isExpired(clock.instant(), refreshSeconds)) {
                if (log.isDebugEnabled()) {
                    log.debug("Returning cached region {} for host: {}", cached.region.id(), lookupHost);
                }
                return cached.region;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Resolving region via TXT record for host: {}", lookupHost);
        }
        String regionId = resolveTxtRecord(lookupHost);
        Region region = Region.of(regionId);

        if (refreshSeconds > 0) {
            cache.put(lookupHost, new CachedRegion(region, clock.instant()));
        }

        return region;
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
            Hashtable<String, String> env = new Hashtable<>();
            env.put(DirContext.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            DirContext ctx = new InitialDirContext(env);
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

    private static long parseRefreshSeconds(Map<String, String> config) {
        if (config == null) {
            return DEFAULT_REFRESH_SECONDS;
        }
        String value = config.get(REFRESH_SECONDS_KEY);
        if (value == null || value.isBlank()) {
            return DEFAULT_REFRESH_SECONDS;
        }
        try {
            long parsed = Long.parseLong(value.trim());
            return Math.max(0, parsed);
        } catch (NumberFormatException e) {
            log.warn("Invalid value for {}: '{}'. Using default {}s.",
                    REFRESH_SECONDS_KEY, value, DEFAULT_REFRESH_SECONDS);
            return DEFAULT_REFRESH_SECONDS;
        }
    }

    private static class CachedRegion {
        final Region region;
        final Instant resolvedAt;

        CachedRegion(Region region, Instant resolvedAt) {
            this.region = region;
            this.resolvedAt = resolvedAt;
        }

        boolean isExpired(Instant now, long refreshSeconds) {
            return resolvedAt.plusSeconds(refreshSeconds).isBefore(now);
        }
    }
}
