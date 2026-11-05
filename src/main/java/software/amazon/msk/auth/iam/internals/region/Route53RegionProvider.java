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
 * A {@link ConfigurableRegionProvider} that resolves the AWS region from a DNS TXT record, with
 * time-based caching.
 *
 * <p>For the parameter list see the Custom Region Provider section of the README. When no
 * {@code host} is configured the lookup name is the supplied host prefixed with {@code "region."},
 * for example {@code region.broker.example.com}.
 *
 * <p>Only the first TXT value is read: the record is expected to be a dedicated,
 * environment-controlled record whose sole value is the active AWS region id.
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
