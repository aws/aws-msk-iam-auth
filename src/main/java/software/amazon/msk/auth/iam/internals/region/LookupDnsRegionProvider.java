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
import java.time.Clock;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.naming.NameNotFoundException;
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
 * address</em> of a bootstrap DNS name rather than from a record on the name itself, with
 * time-based caching.
 *
 * <p>Suits layouts where a stable bootstrap name repoints between clusters in different regions and
 * the active region is signalled by the network it resolves into. The bootstrap A record is
 * resolved, the {@code masking} prefix length applied to get the network prefix, that prefix
 * dash-encoded into a label and prepended to the host to form a TXT lookup name (for example
 * {@code 10-218-0-0.msk.example.com}), whose value is the region id. For the parameter list see the
 * Custom Region Provider section of the README.
 *
 * <p>Both lookups go through JNDI DNS rather than {@link InetAddress}; see
 * {@link #resolveHostAddresses(String)} for why that matters. IPv4 only: an IPv6 address cannot be
 * masked into a dotted-quad network prefix.
 */
public class LookupDnsRegionProvider implements ConfigurableRegionProvider {
    private static final Logger log = LoggerFactory.getLogger(LookupDnsRegionProvider.class);

    private static final String MASKING_KEY = "masking";

    private final String host;
    private final NetworkPrefix networkPrefix;
    private final long dnsTimeoutMs;
    private final int dnsRetries;
    private final CachedRegionResolver cache;

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
        this.host = config.get(RegionProviderConfig.HOST_KEY);
        this.networkPrefix = NetworkPrefix.parse(maskingParam);
        this.dnsTimeoutMs = RegionProviderConfig.parseLong(config,
                RegionProviderConfig.DNS_TIMEOUT_MS_KEY, RegionProviderConfig.DEFAULT_DNS_TIMEOUT_MS, 1);
        this.dnsRetries = RegionProviderConfig.parseBoundedInt(config,
                RegionProviderConfig.DNS_RETRIES_KEY, RegionProviderConfig.DEFAULT_DNS_RETRIES, 0);
        long refreshSeconds = RegionProviderConfig.parseLong(config,
                RegionProviderConfig.REFRESH_SECONDS_KEY, RegionProviderConfig.DEFAULT_REFRESH_SECONDS, 0);
        this.cache = new CachedRegionResolver(refreshSeconds, clock);
        if (log.isDebugEnabled()) {
            log.debug("LookupDnsRegionProvider initialized with host={}, masking=/{}, "
                            + "refresh.seconds={}, dns.timeout.ms={}, dns.retries={}",
                    this.host, this.networkPrefix.prefixLength(), refreshSeconds,
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
        String bootstrapHost = RegionUtils.normalizeHost(configuredOrSupplied);

        // The cache is keyed by the bootstrap host. On a cluster swap the resolved IP changes,
        // producing a different TXT lookup name and region; the TTL bounds how stale the cached
        // region may be before we re-resolve and pick up the new cluster's region.
        return cache.resolve(bootstrapHost, () -> resolve(bootstrapHost));
    }

    private Region resolve(String bootstrapHost) {
        Set<String> ips = resolveHostAddresses(bootstrapHost);
        if (ips == null || ips.isEmpty()) {
            throw SdkClientException.create("Could not resolve any IP for host: " + bootstrapHost);
        }
        // Only IPv4 can be masked into a dotted-quad network prefix. Discard anything else before
        // sorting: an IPv6 literal left in the set could sort first (2001:db8::1 sorts before
        // 203.0.113.5) and fail the mask, and because that depends on the particular addresses
        // returned, a dual-stack bootstrap name would fail only intermittently.
        Set<String> ipv4 = ips.stream()
                .filter(ip -> ip != null && !ip.isBlank() && !ip.contains(":"))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (ipv4.isEmpty()) {
            throw SdkClientException.create("Host " + bootstrapHost + " resolved only to non-IPv4 "
                    + "addresses " + ips + "; this provider masks IPv4 addresses into a network "
                    + "prefix and cannot derive a region from an IPv6 address");
        }
        // Deterministically pick the lowest-sorted IP so multiple A records in the same network
        // prefix yield a stable lookup name.
        String ip = ipv4.stream().sorted().findFirst().orElseThrow();

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
        Region region = RegionProviderConfig.validateRegionId(
                regionId.get(), "the TXT record at " + lookupHost);
        if (log.isDebugEnabled()) {
            log.debug("Resolved region '{}' for bootstrap host {} (ip={}, txt={})",
                    region.id(), bootstrapHost, ip, lookupHost);
        }
        return region;
    }

    /**
     * Resolves the A records of the given hostname to a set of IPv4 address literals, using JNDI
     * with the {@code com.sun.jndi.dns.DnsContextFactory} built-in JDK DNS provider — the same
     * mechanism as {@link #resolveTxtRecord(String)}.
     *
     * <p>Deliberately not {@link InetAddress#getAllByName(String)}: that answers from the JVM-wide
     * address cache, whose default positive TTL is 30 seconds and is unbounded under a security
     * manager, so a repointed bootstrap name would keep resolving to the old network well past this
     * provider's own {@code refresh.seconds} — including when caching is disabled. It also returns
     * AAAA records, which cannot be masked into an IPv4 prefix.</p>
     *
     * @param lookupHost the hostname to resolve.
     * @return the resolved address literals; an empty set if the host has no A record.
     * @throws SdkClientException if the DNS lookup fails.
     */
    Set<String> resolveHostAddresses(String lookupHost) {
        try {
            DirContext ctx = new InitialDirContext(
                    RegionProviderConfig.dnsEnv(dnsTimeoutMs, dnsRetries));
            try {
                Attributes attrs = ctx.getAttributes(lookupHost, new String[]{"A"});
                Attribute aAttr = attrs.get("A");
                if (aAttr == null || aAttr.size() == 0) {
                    return Set.of();
                }
                Set<String> addresses = new LinkedHashSet<>();
                NamingEnumeration<?> values = aAttr.getAll();
                while (values.hasMore()) {
                    String value = String.valueOf(values.next()).trim();
                    if (!value.isEmpty()) {
                        addresses.add(value);
                    }
                }
                return Collections.unmodifiableSet(addresses);
            } finally {
                ctx.close();
            }
        } catch (NameNotFoundException e) {
            // The name does not exist at all; let the caller report it as an unresolvable
            // bootstrap host rather than as a DNS failure.
            return Set.of();
        } catch (NamingException e) {
            throw SdkClientException.create(
                    "Failed to resolve A record for host: " + lookupHost, e);
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
            DirContext ctx = new InitialDirContext(
                    RegionProviderConfig.dnsEnv(dnsTimeoutMs, dnsRetries));
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

}
