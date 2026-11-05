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
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

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
 * A {@link ConfigurableRegionProvider} that resolves the AWS region by following a hostname's CNAME
 * chain and reading the region out of the names it resolves to, with time-based caching.
 *
 * <p>For the DNS layout this expects and the full parameter list ({@code suffix}, {@code max.hops},
 * {@code host}, plus the shared caching and DNS parameters), see the Custom Region Provider section
 * of the README. Two constraints are easy to get wrong: the record at the top of the chain must be
 * a CNAME rather than a Route 53 alias, which resolves internally and yields no hostname to read a
 * region from; and the starting hostname must carry no region id, or {@link RegionUtils} resolves
 * it directly and never consults this provider.
 *
 * <p>Resolution order per hostname is the AWS endpoint parse, then — for names the configured
 * {@code suffix} covers — the label immediately before that suffix and nothing else, then a
 * label-exact scan for names the suffix does not cover. See {@link #suffixCovers(String)} for why
 * the suffix is exclusive, and {@code resolveRegionViaCnameChain} for how a merely region-shaped
 * label is held as provisional while the walk continues.
 *
 * <p>When no name in the chain yields a region an {@link SdkClientException} is thrown, which
 * {@link RegionUtils} treats as a failed provider and falls back to the
 * {@code DefaultAwsRegionProviderChain}.
 */
public class CnameRegionProvider implements ConfigurableRegionProvider {
    private static final Logger log = LoggerFactory.getLogger(CnameRegionProvider.class);

    private static final String SUFFIX_KEY = "suffix";
    private static final String MAX_HOPS_KEY = "max.hops";

    private static final int DEFAULT_MAX_HOPS = 3;

    private final String host;
    private final String suffix;
    private final int maxHops;
    private final long dnsTimeoutMs;
    private final int dnsRetries;
    private final CachedRegionResolver cache;

    public CnameRegionProvider(Map<String, String> config) {
        this(config, Clock.systemUTC());
    }

    // Visible for testing
    CnameRegionProvider(Map<String, String> config, Clock clock) {
        this.host = config != null ? config.get(RegionProviderConfig.HOST_KEY) : null;
        this.suffix = normalizeSuffix(config != null ? config.get(SUFFIX_KEY) : null);
        this.maxHops = RegionProviderConfig.parseBoundedInt(config, MAX_HOPS_KEY, DEFAULT_MAX_HOPS, 1);
        this.dnsTimeoutMs = RegionProviderConfig.parseLong(config,
                RegionProviderConfig.DNS_TIMEOUT_MS_KEY, RegionProviderConfig.DEFAULT_DNS_TIMEOUT_MS, 1);
        this.dnsRetries = RegionProviderConfig.parseBoundedInt(config,
                RegionProviderConfig.DNS_RETRIES_KEY, RegionProviderConfig.DEFAULT_DNS_RETRIES, 0);
        long refreshSeconds = RegionProviderConfig.parseLong(config,
                RegionProviderConfig.REFRESH_SECONDS_KEY, RegionProviderConfig.DEFAULT_REFRESH_SECONDS, 0);
        this.cache = new CachedRegionResolver(refreshSeconds, clock);
        if (log.isDebugEnabled()) {
            log.debug("CnameRegionProvider initialized with host={}, suffix={}, max.hops={}, "
                            + "refresh.seconds={}, dns.timeout.ms={}, dns.retries={}",
                    this.host, this.suffix, this.maxHops, refreshSeconds,
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
        return cache.resolve(startHost, () -> resolveRegionViaCnameChain(startHost));
    }

    /**
     * Walks the CNAME chain from {@code startHost}, examining each name for a region.
     *
     * <p>A <em>verified</em> region ends the walk immediately. A name that only yields a
     * region-shaped label is kept as a provisional answer and the walk continues, because a later
     * name in the chain may yield a verified one — a chain through
     * {@code kafka.us-prod-1.customer.com} to {@code nlb-abc.elb.us-east-1.amazonaws.com} must
     * resolve {@code us-east-1}, not the environment label that merely looks like a region. The
     * provisional answer is used only when the whole chain produces nothing better, which is what
     * keeps a region launched after this SDK release resolving.</p>
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
        Optional<Region> verified = extractVerifiedRegion(current);
        Optional<Region> provisional = Optional.empty();
        String provisionalHost = null;
        if (verified.isEmpty()) {
            provisional = extractProvisionalRegion(current);
            provisionalHost = provisional.isPresent() ? current : null;
        }

        for (int hop = 0; hop < maxHops && verified.isEmpty(); hop++) {
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
            verified = extractVerifiedRegion(current);
            if (verified.isEmpty() && provisional.isEmpty()) {
                provisional = extractProvisionalRegion(current);
                if (provisional.isPresent()) {
                    provisionalHost = current;
                }
            }
        }

        if (verified.isPresent()) {
            return verified.get();
        }
        if (provisional.isPresent()) {
            Region region = provisional.get();
            log.warn("Signing region '{}' was taken from host {} because its label matches an AWS "
                            + "region naming pattern, but it is not a region this SDK release knows and "
                            + "no other name in the chain {} yielded a known region. If '{}' is not a "
                            + "real region (for example an environment label that happens to look like "
                            + "one), authentication will fail; otherwise upgrade the SDK to recognise it.",
                    region.id(), provisionalHost, String.join(" -> ", visited), region.id());
            return region;
        }
        throw SdkClientException.create(
                "Could not determine a region from the CNAME chain " + String.join(" -> ", visited)
                        + " (max.hops=" + maxHops + ")");
    }

    /**
     * Reads a region out of a single hostname, accepting only answers that are trustworthy on their
     * own: the AWS endpoint parse, where the label sits in the region position of a name inside an
     * AWS-owned DNS suffix, and a label that is a region this SDK knows.
     */
    private Optional<Region> extractVerifiedRegion(String bareHost) {
        Optional<Region> endpointRegion = RegionUtils.extractRegionFromEndpointHost(bareHost);
        if (endpointRegion.isPresent()) {
            return endpointRegion;
        }
        if (suffixCovers(bareHost)) {
            return anchoredLabel(bareHost, RegionUtils::knownRegionFromLabel);
        }
        return RegionUtils.extractKnownRegionFromHostLabels(bareHost);
    }

    /**
     * Reads a region-shaped but unverified label out of a customer-owned hostname. Only called
     * after {@link #extractVerifiedRegion(String)} has come back empty, so any answer here matches
     * a partition naming pattern without being a region this SDK knows.
     */
    private Optional<Region> extractProvisionalRegion(String bareHost) {
        if (suffixCovers(bareHost)) {
            return anchoredLabel(bareHost, RegionUtils::regionFromLabel);
        }
        return RegionUtils.extractRegionFromHostLabels(bareHost);
    }

    /**
     * Whether the configured {@code suffix} covers this hostname, meaning the caller has told us
     * exactly which label position holds the region for names in this domain.
     *
     * <p>When it does, that position is the <em>only</em> answer this hostname can give, and a
     * hostname whose anchored label is not a region yields nothing at all. Falling back to a scan
     * of the other labels would defeat the parameter: a proxy hop such as
     * {@code us-east-1.edge.customer.com} in a chain that ends at a {@code us-west-2} cluster
     * anchors on {@code edge}, which is not a region, but carries {@code us-east-1} in another
     * position. Accepting that would stop the walk and sign every request for the wrong region,
     * with no error to fall back from.
     *
     * <p>Hostnames the suffix does not cover keep the broader interpretation, because a name
     * part-way along the chain can legitimately sit outside the caller's own domain and the scan is
     * then the best signal available.</p>
     */
    private boolean suffixCovers(String bareHost) {
        return suffix != null && bareHost.endsWith("." + suffix);
    }

    /**
     * The label directly before the configured suffix. Only valid when {@link #suffixCovers} holds.
     */
    private Optional<Region> anchoredLabel(String bareHost,
                                           Function<String, Optional<Region>> labelParser) {
        String head = bareHost.substring(0, bareHost.length() - suffix.length() - 1);
        return labelParser.apply(head.substring(head.lastIndexOf('.') + 1));
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
            DirContext ctx = new InitialDirContext(
                    RegionProviderConfig.dnsEnv(dnsTimeoutMs, dnsRetries));
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
}
