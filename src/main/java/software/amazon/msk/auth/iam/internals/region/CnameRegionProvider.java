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
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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
 * A {@link ConfigurableRegionProvider} that resolves the AWS region by following the CNAME chain
 * of a hostname and reading the region out of the names it resolves to, with time-based caching.
 *
 * <p>This suits DNS layouts where a single stable endpoint name is a Route 53 failover CNAME over
 * per-region names in a customer-owned domain, so the active region is whichever name the alias
 * currently points at:</p>
 *
 * <pre>
 *   msk.customer.com          CNAME (failover) -&gt; msk.us-east-1.customer.com -&gt; NLB in us-east-1
 *                                              -&gt; msk.us-west-2.customer.com -&gt; NLB in us-west-2
 * </pre>
 *
 * <p>Because the record at the top of the chain must be a CNAME, this provider cannot resolve a
 * layout whose stable name is a Route 53 <em>alias</em> record pointing straight at a load
 * balancer: Route 53 resolves alias records internally, so the response carries only address
 * records and no target hostname to read a region from.</p>
 *
 * <p>Configuration parameters (passed via constructor map):</p>
 * <ul>
 *   <li>{@code host} — optional fully-qualified hostname to start the chain from. When provided,
 *       this value is used instead of the host supplied to {@link #getRegion(String)}. Set it to
 *       use this provider on the OAuth path, where no broker hostname is available and the no-arg
 *       {@link #getRegion()} is called.</li>
 *   <li>{@code suffix} — optional domain suffix owned by the caller, for example
 *       {@code customer.com}. When a resolved name ends with this suffix, the region is the label
 *       immediately before it, which pins the region to one position in the name and cannot be
 *       confused by a region-shaped label elsewhere. A leading dot is optional.</li>
 *   <li>{@code max.hops} — how many CNAME lookups to follow before giving up. Defaults to 3, with
 *       a floor of 1. Each hop is a sequential DNS round trip on the authentication path, so raise
 *       this only as far as the chain actually requires.</li>
 *   <li>{@code refresh.seconds} — how often, in seconds, the cached region value is refreshed by
 *       walking the chain again. Defaults to 60 (1 minute). Set to 0 to disable caching and resolve
 *       DNS on every call. Lazily evaluated: the cache is only refreshed when an authentication
 *       request needs to be signed. Note the failover implication — for up to this long after the
 *       alias flips, requests are signed for the previous region and fail, until the entry expires
 *       and the client's next authentication attempt picks up the new region.</li>
 *   <li>{@code dns.timeout.ms} — initial DNS query timeout in milliseconds. Defaults to 1000.</li>
 *   <li>{@code dns.retries} — how many times a DNS query is retried, each retry doubling the
 *       timeout. Defaults to 2. Together with {@code dns.timeout.ms} this bounds how long an
 *       unresponsive resolver can stall authentication, which matters here because a chain costs
 *       one lookup per hop.</li>
 * </ul>
 *
 * <p>Every name in the chain, starting with the host itself, is examined in three ways: the
 * AWS endpoint parse (so a chain terminating at a real AWS name such as
 * {@code ...elb.us-east-1.amazonaws.com} resolves precisely), then the configured {@code suffix}
 * anchor, then a label-exact scan of the whole name. The first name that yields a region ends the
 * walk, so no more DNS lookups are made than needed.</p>
 *
 * <p>When no name in the chain yields a region, an {@link SdkClientException} is thrown, which
 * {@link RegionUtils} treats as a failed provider and falls back to the
 * {@code DefaultAwsRegionProviderChain}.</p>
 */
public class CnameRegionProvider implements ConfigurableRegionProvider {
    private static final Logger log = LoggerFactory.getLogger(CnameRegionProvider.class);

    private static final String HOST_KEY = "host";
    private static final String SUFFIX_KEY = "suffix";
    private static final String MAX_HOPS_KEY = "max.hops";
    private static final String REFRESH_SECONDS_KEY = "refresh.seconds";
    private static final String DNS_TIMEOUT_MS_KEY = "dns.timeout.ms";
    private static final String DNS_RETRIES_KEY = "dns.retries";

    private static final int DEFAULT_MAX_HOPS = 3;
    private static final long DEFAULT_REFRESH_SECONDS = 60;
    private static final long DEFAULT_DNS_TIMEOUT_MS = 1000;
    private static final int DEFAULT_DNS_RETRIES = 2;

    private final String host;
    private final String suffix;
    private final int maxHops;
    private final long refreshSeconds;
    private final long dnsTimeoutMs;
    private final int dnsRetries;
    private final Clock clock;
    private final ConcurrentHashMap<String, CachedRegion> cache = new ConcurrentHashMap<>();

    public CnameRegionProvider(Map<String, String> config) {
        this(config, Clock.systemUTC());
    }

    // Visible for testing
    CnameRegionProvider(Map<String, String> config, Clock clock) {
        this.host = config != null ? config.get(HOST_KEY) : null;
        this.suffix = normalizeSuffix(config != null ? config.get(SUFFIX_KEY) : null);
        this.maxHops = (int) parseLongParam(config, MAX_HOPS_KEY, DEFAULT_MAX_HOPS, 1);
        this.refreshSeconds = parseLongParam(config, REFRESH_SECONDS_KEY, DEFAULT_REFRESH_SECONDS, 0);
        this.dnsTimeoutMs = parseLongParam(config, DNS_TIMEOUT_MS_KEY, DEFAULT_DNS_TIMEOUT_MS, 1);
        this.dnsRetries = (int) parseLongParam(config, DNS_RETRIES_KEY, DEFAULT_DNS_RETRIES, 0);
        this.clock = clock;
        if (log.isDebugEnabled()) {
            log.debug("CnameRegionProvider initialized with host={}, suffix={}, max.hops={}, "
                            + "refresh.seconds={}, dns.timeout.ms={}, dns.retries={}",
                    this.host, this.suffix, this.maxHops, this.refreshSeconds,
                    this.dnsTimeoutMs, this.dnsRetries);
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
        String startHost = RegionUtils.normalizeHost(configuredOrSupplied);

        if (refreshSeconds > 0) {
            CachedRegion cached = cache.get(startHost);
            if (cached != null && !cached.isExpired(clock.instant(), refreshSeconds)) {
                if (log.isDebugEnabled()) {
                    log.debug("Returning cached region {} for host: {}", cached.region.id(), startHost);
                }
                return cached.region;
            }
        }

        Region region = resolveRegionViaCnameChain(startHost);

        if (refreshSeconds > 0) {
            cache.put(startHost, new CachedRegion(region, clock.instant()));
        }

        return region;
    }

    /**
     * Walks the CNAME chain from {@code startHost}, examining each name for a region and stopping
     * at the first one that yields it.
     *
     * <p>The walk also stops when a name has no CNAME record — the end of the chain — and when a
     * name repeats, which would otherwise spin on a misconfigured DNS loop.</p>
     *
     * @param startHost the normalized hostname to start from.
     * @return the resolved region.
     * @throws SdkClientException if the chain ends, loops or exhausts {@code max.hops} without
     *                            yielding a region, or if a DNS lookup fails.
     */
    private Region resolveRegionViaCnameChain(String startHost) {
        Set<String> visited = new LinkedHashSet<>();
        visited.add(startHost);
        String current = startHost;
        Optional<Region> region = extractRegion(current);

        for (int hop = 0; hop < maxHops && region.isEmpty(); hop++) {
            if (log.isDebugEnabled()) {
                log.debug("Resolving CNAME for host: {} (hop {} of {})", current, hop + 1, maxHops);
            }
            String target = resolveCname(current);
            if (target == null || target.isBlank()) {
                if (log.isDebugEnabled()) {
                    log.debug("Host {} has no CNAME record; end of chain.", current);
                }
                break;
            }
            String next = RegionUtils.normalizeHost(target);
            if (!visited.add(next)) {
                log.warn("CNAME chain from {} loops back to {}; stopping the walk.", startHost, next);
                break;
            }
            current = next;
            region = extractRegion(current);
        }

        return region.orElseThrow(() -> SdkClientException.create(
                "Could not determine a region from the CNAME chain " + String.join(" -> ", visited)
                        + " (max.hops=" + maxHops + ")"));
    }

    /**
     * Reads a region out of a single hostname, from the most precise interpretation to the least:
     * the AWS endpoint parse, then the configured {@code suffix} anchor, then a label-exact scan.
     *
     * <p>The label scan still runs when a {@code suffix} is configured but does not match, because
     * a name part-way along the chain can legitimately sit outside the caller's own domain.</p>
     */
    private Optional<Region> extractRegion(String bareHost) {
        Optional<Region> endpointRegion = RegionUtils.extractRegionFromEndpointHost(bareHost);
        if (endpointRegion.isPresent()) {
            return endpointRegion;
        }
        Optional<Region> suffixRegion = extractRegionFromConfiguredSuffix(bareHost);
        if (suffixRegion.isPresent()) {
            return suffixRegion;
        }
        return RegionUtils.extractRegionFromHostLabels(bareHost);
    }

    /**
     * Anchored parse against the caller's own domain: when the host ends with the configured
     * suffix, the region is the label directly before it.
     */
    private Optional<Region> extractRegionFromConfiguredSuffix(String bareHost) {
        if (suffix == null || !bareHost.endsWith("." + suffix)) {
            return Optional.empty();
        }
        String head = bareHost.substring(0, bareHost.length() - suffix.length() - 1);
        return RegionUtils.regionFromLabel(head.substring(head.lastIndexOf('.') + 1));
    }

    /**
     * Resolves the CNAME target of the given hostname using JNDI with the
     * {@code com.sun.jndi.dns.DnsContextFactory} built-in JDK DNS provider.
     *
     * <p>A name with no CNAME record is the end of the chain rather than an error, and returns
     * null. DNS permits only one CNAME per name, so only the first value is read.</p>
     *
     * @param lookupHost the fully-qualified hostname to query.
     * @return the CNAME target, or null if the host has no CNAME record.
     * @throws SdkClientException if the DNS lookup fails.
     */
    String resolveCname(String lookupHost) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(DirContext.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            env.put("com.sun.jndi.dns.timeout.initial", Long.toString(dnsTimeoutMs));
            env.put("com.sun.jndi.dns.timeout.retries", Integer.toString(dnsRetries));
            DirContext ctx = new InitialDirContext(env);
            try {
                Attributes attrs = ctx.getAttributes(lookupHost, new String[]{"CNAME"});
                Attribute cnameAttr = attrs.get("CNAME");
                if (cnameAttr == null || cnameAttr.size() == 0) {
                    return null;
                }
                if (cnameAttr.size() > 1 && log.isDebugEnabled()) {
                    log.debug("Host {} has {} CNAME records, which DNS does not permit; "
                            + "using the first.", lookupHost, cnameAttr.size());
                }
                return ((String) cnameAttr.get(0)).trim();
            } finally {
                ctx.close();
            }
        } catch (NamingException e) {
            throw SdkClientException.create(
                    "Failed to resolve CNAME record for host: " + lookupHost, e);
        }
    }

    private static String normalizeSuffix(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        while (normalized.startsWith(".")) {
            normalized = normalized.substring(1);
        }
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isEmpty() ? null : normalized;
    }

    private static long parseLongParam(Map<String, String> config, String key, long defaultValue,
                                      long minimum) {
        if (config == null) {
            return defaultValue;
        }
        String value = config.get(key);
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
