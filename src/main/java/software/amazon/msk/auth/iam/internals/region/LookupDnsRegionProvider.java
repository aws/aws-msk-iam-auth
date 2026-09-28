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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

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
import software.amazon.msk.auth.iam.internals.utils.RegionUtils;

/**
 * A {@link ConfigurableRegionProvider} that resolves the AWS region from the <em>resolved IP
 * address</em> of a bootstrap DNS name, rather than from a fixed record on the name itself, with
 * time-based caching.
 *
 * <p>This suits layouts where a single stable bootstrap name (e.g. {@code msk.example.com}) can
 * repoint from a cluster in one region to a cluster in another, and the active region is signalled
 * by the network the name currently resolves into. Because the SigV4 signature must be signed for
 * the region the cluster actually lives in, the signing region is discovered from wherever the
 * bootstrap name currently resolves.</p>
 *
 * <p>Resolution flow:</p>
 * <ol>
 *   <li>Resolve the bootstrap {@code host} A record to an IP, e.g. {@code 10.218.4.7}. When the
 *       name has several A records, the lowest-sorted address is chosen so records sharing a
 *       network prefix still yield one stable lookup name.</li>
 *   <li>Apply the {@code masking} CIDR prefix length (e.g. {@code /16}) to that IP to get the
 *       network prefix, e.g. {@code 10.218.0.0}.</li>
 *   <li>Dash-encode the prefix and prepend it to {@code host} to build the TXT lookup name,
 *       e.g. {@code 10-218-0-0.msk.example.com}.</li>
 *   <li>Resolve that TXT record to a region id, e.g. {@code "us-east-1"}, and return
 *       {@link Region#of(String)}.</li>
 * </ol>
 *
 * <p>Configuration parameters (passed via constructor map):</p>
 * <ul>
 *   <li>{@code host} — optional bootstrap hostname to resolve. When provided, this value is used
 *       instead of the host supplied to {@link #getRegion(String)}. Set it to use this provider on
 *       the OAuth path, where no broker hostname is available and the no-arg {@link #getRegion()}
 *       is called.</li>
 *   <li>{@code masking} — required. CIDR-style mask whose prefix length is applied to the resolved
 *       IP, e.g. {@code 0.0.0.0/16}. Only the {@code /NN} portion matters; the address portion is
 *       ignored. Must be octet-aligned ({@code /8}, {@code /16}, {@code /24}, {@code /32}).</li>
 *   <li>{@code refresh.seconds} — how often, in seconds, the cached region value is refreshed by
 *       resolving DNS again. Defaults to 60 (1 minute). Set to 0 to disable caching and resolve DNS
 *       on every call. Lazily evaluated: the cache is only refreshed when an authentication request
 *       needs to be signed. Note the failover implication — for up to this long after the bootstrap
 *       name repoints, requests are signed for the previous region and fail, until the entry
 *       expires and the client's next authentication attempt picks up the new region.</li>
 * </ul>
 *
 * <p>When the bootstrap IP or the region TXT record cannot be resolved, an
 * {@link SdkClientException} is thrown, which {@link RegionUtils} treats as a failed provider and
 * falls back to the {@code DefaultAwsRegionProviderChain}.</p>
 */
public class LookupDnsRegionProvider implements ConfigurableRegionProvider {
    private static final Logger log = LoggerFactory.getLogger(LookupDnsRegionProvider.class);

    private static final String HOST_KEY = "host";
    private static final String MASKING_KEY = "masking";
    private static final String REFRESH_SECONDS_KEY = "refresh.seconds";
    private static final long DEFAULT_REFRESH_SECONDS = 60;

    private final String host;
    private final NetworkPrefix networkPrefix;
    private final long refreshSeconds;
    private final Clock clock;
    private final ConcurrentHashMap<String, CachedRegion> cache = new ConcurrentHashMap<>();

    public LookupDnsRegionProvider(Map<String, String> config) {
        this(config, Clock.systemUTC());
    }

    // Visible for testing
    LookupDnsRegionProvider(Map<String, String> config, Clock clock) {
        String maskingParam = config != null ? config.get(MASKING_KEY) : null;
        if (maskingParam == null || maskingParam.isBlank()) {
            throw new IllegalArgumentException(
                    "LookupDnsRegionProvider requires a '" + MASKING_KEY + "' parameter (e.g. 0.0.0.0/16)");
        }
        this.host = config.get(HOST_KEY);
        this.networkPrefix = NetworkPrefix.parse(maskingParam);
        this.refreshSeconds = parseRefreshSeconds(config);
        this.clock = clock;
        if (log.isDebugEnabled()) {
            log.debug("LookupDnsRegionProvider initialized with host={}, masking=/{}, refresh.seconds={}",
                    this.host, this.networkPrefix.prefixLength(), this.refreshSeconds);
        }
    }

    @Override
    public Region getRegion() {
        return getRegion(null);
    }

    @Override
    public Region getRegion(String host) {
        String configuredOrSupplied = this.host != null ? this.host : host;
        if (configuredOrSupplied == null || configuredOrSupplied.isBlank()) {
            throw SdkClientException.create(
                    "Cannot resolve region: no host configured and no host parameter provided");
        }
        String bootstrapHost = RegionUtils.normalizeHost(configuredOrSupplied);

        // The cache is keyed by the bootstrap host. On a cluster swap the resolved IP changes,
        // producing a different TXT lookup name and region; the TTL bounds how stale the cached
        // region may be before we re-resolve and pick up the new cluster's region.
        if (refreshSeconds > 0) {
            CachedRegion cached = cache.get(bootstrapHost);
            if (cached != null && !cached.isExpired(clock.instant(), refreshSeconds)) {
                if (log.isDebugEnabled()) {
                    log.debug("Returning cached region {} for host: {}", cached.region.id(), bootstrapHost);
                }
                return cached.region;
            }
        }

        Region region = resolve(bootstrapHost);

        if (refreshSeconds > 0) {
            cache.put(bootstrapHost, new CachedRegion(region, clock.instant()));
        }
        return region;
    }

    private Region resolve(String bootstrapHost) {
        Set<String> ips = resolveHostAddresses(bootstrapHost);
        if (ips == null || ips.isEmpty()) {
            throw SdkClientException.create("Could not resolve any IP for host: " + bootstrapHost);
        }
        // Deterministically pick the lowest-sorted IP so multiple A records in the same network
        // prefix yield a stable lookup name.
        String ip = ips.stream().sorted().findFirst().orElseThrow();

        String label = networkPrefix.toDashedLabel(ip);
        String lookupHost = label + "." + bootstrapHost;

        if (log.isDebugEnabled()) {
            log.debug("Resolved {} -> {}; network-prefix label={}; TXT lookup={}",
                    bootstrapHost, ip, label, lookupHost);
        }

        Optional<String> regionId = resolveTxtRecord(lookupHost);
        if (regionId.isEmpty() || regionId.get().isBlank()) {
            throw SdkClientException.create(
                    "No region TXT record found at: " + lookupHost + " (for bootstrap IP " + ip + ")");
        }
        Region region = Region.of(regionId.get());
        if (log.isDebugEnabled()) {
            log.debug("Resolved region '{}' for bootstrap host {} (ip={}, txt={})",
                    region.id(), bootstrapHost, ip, lookupHost);
        }
        return region;
    }

    /**
     * Resolves the A/AAAA records of the given hostname to a set of address literals, using
     * {@link InetAddress#getAllByName(String)}.
     *
     * @param lookupHost the hostname to resolve.
     * @return the resolved address literals; an empty set if the host cannot be resolved.
     */
    Set<String> resolveHostAddresses(String lookupHost) {
        try {
            InetAddress[] addrs = InetAddress.getAllByName(lookupHost);
            return Arrays.stream(addrs)
                    .map(InetAddress::getHostAddress)
                    .collect(Collectors.toUnmodifiableSet());
        } catch (UnknownHostException e) {
            return Set.of();
        }
    }

    /**
     * Resolves a DNS TXT record for the given hostname using JNDI with the
     * {@code com.sun.jndi.dns.DnsContextFactory} built-in JDK DNS provider.
     *
     * <p>Only the first TXT record value is used. This is intentional — the TXT record is expected
     * to be a dedicated, environment-controlled record whose sole value is the active AWS region
     * id. Surrounding quotes are stripped from the returned value.</p>
     *
     * @param lookupHost the fully-qualified hostname to query.
     * @return the TXT record value (unquoted and trimmed), or empty if no TXT record is found.
     * @throws SdkClientException if the DNS lookup fails.
     */
    Optional<String> resolveTxtRecord(String lookupHost) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(DirContext.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            DirContext ctx = new InitialDirContext(env);
            try {
                Attributes attrs = ctx.getAttributes(lookupHost, new String[]{"TXT"});
                Attribute txtAttr = attrs.get("TXT");
                if (txtAttr == null || txtAttr.size() == 0) {
                    return Optional.empty();
                }
                NamingEnumeration<?> values = txtAttr.getAll();
                String value = (String) values.next();
                return Optional.of(value.replace("\"", "").trim());
            } finally {
                ctx.close();
            }
        } catch (NamingException e) {
            throw SdkClientException.create(
                    "Failed to resolve TXT record for host: " + lookupHost, e);
        }
    }

    private static long parseRefreshSeconds(Map<String, String> config) {
        String value = config != null ? config.get(REFRESH_SECONDS_KEY) : null;
        if (value == null || value.isBlank()) {
            return DEFAULT_REFRESH_SECONDS;
        }
        try {
            return Math.max(0, Long.parseLong(value.trim()));
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
