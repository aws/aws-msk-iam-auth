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
 * a DNS TXT record lookup via Route 53.
 *
 * <p>Configuration parameters (passed via constructor map):</p>
 * <ul>
 *   <li>{@code host} — optional fully-qualified hostname to query for the TXT record.
 *       When provided, this value is used directly as the DNS lookup name.</li>
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
    private static final String REGION_PREFIX = "region.";
    private static final Logger log = LoggerFactory.getLogger(Route53RegionProvider.class);
    private static final String HOST_KEY = "host";

    private final String host;

    public Route53RegionProvider(Map<String, String> config) {
        this.host = config != null ? config.get(HOST_KEY) : null;
        if (log.isDebugEnabled()) {
            log.debug("Route53RegionProvider initialized with host={}", this.host);
        }
    }

    /**
     * Resolve the region using the configured host. Throws if no host was
     * configured and no fallback host is available.
     */
    @Override
    public Region getRegion() {
        return getRegion(null);
    }

    /**
     * Resolve the region by looking up a DNS TXT record.
     *
     * <p>If a {@code host} was provided at construction time, that value is used
     * as the DNS name. Otherwise the given {@code host} parameter is prefixed
     * with {@code "region."} to form the lookup name.</p>
     *
     * @param host fallback host used when no host was configured at construction
     * @return the resolved AWS {@link Region}
     * @throws SdkClientException if the region cannot be resolved
     */
    public Region getRegion(String host) {
        String lookupHost = this.host != null ? this.host : buildLookupHost(host);
        if (lookupHost == null || lookupHost.isBlank()) {
            throw SdkClientException.create(
                    "Cannot resolve region: no host configured and no host parameter provided");
        }
        if (log.isDebugEnabled()) {
            log.debug("Resolving region via TXT record for host: {}", lookupHost);
        }
        String regionId = resolveTxtRecord(lookupHost);
        return Region.of(regionId);
    }

    private String buildLookupHost(String host) {
        if (host == null || host.isBlank()) {
            return null;
        }
        return REGION_PREFIX + host;
    }

    private String resolveTxtRecord(String lookupHost) {
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
                // TXT records may be quoted
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
