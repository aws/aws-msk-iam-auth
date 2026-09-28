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
import java.time.ZoneId;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class LookupDnsRegionProviderTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2025-01-01T00:00:00Z"), ZoneId.of("UTC"));

    private static final String BOOTSTRAP = "msk.example.com";

    /**
     * Builds a provider whose A-record and TXT lookups are served from in-memory maps instead of
     * real DNS. {@code ips} maps a hostname to its resolved addresses; {@code txt} maps a lookup
     * name to its region TXT value. A host absent from a map resolves to nothing.
     */
    private LookupDnsRegionProvider provider(Map<String, String> config,
                                            Clock clock,
                                            Map<String, Set<String>> ips,
                                            Map<String, String> txt,
                                            AtomicInteger txtLookups) {
        return new LookupDnsRegionProvider(config, clock) {
            @Override
            Set<String> resolveHostAddresses(String lookupHost) {
                return ips.getOrDefault(lookupHost, Set.of());
            }

            @Override
            Optional<String> resolveTxtRecord(String lookupHost) {
                txtLookups.incrementAndGet();
                return Optional.ofNullable(txt.get(lookupHost));
            }
        };
    }

    private static Map<String, String> config(String... keyValuePairs) {
        Map<String, String> config = new HashMap<>();
        for (int i = 0; i < keyValuePairs.length; i += 2) {
            config.put(keyValuePairs[i], keyValuePairs[i + 1]);
        }
        return config;
    }

    @Test
    public void testConstructorRequiresMaskingParameter() {
        assertThrows(IllegalArgumentException.class,
                () -> new LookupDnsRegionProvider(config("host", BOOTSTRAP)));
    }

    @Test
    public void testConstructorRejectsNullConfig() {
        assertThrows(IllegalArgumentException.class,
                () -> new LookupDnsRegionProvider((Map<String, String>) null));
    }

    @Test
    public void testGetRegionNoHostConfiguredAndNullParam() {
        LookupDnsRegionProvider provider =
                new LookupDnsRegionProvider(config("masking", "0.0.0.0/16"));
        assertThrows(SdkClientException.class, () -> provider.getRegion(null));
    }

    @Test
    public void testGetRegionNoHostConfiguredAndBlankParam() {
        LookupDnsRegionProvider provider =
                new LookupDnsRegionProvider(config("masking", "0.0.0.0/16"));
        assertThrows(SdkClientException.class, () -> provider.getRegion("  "));
    }

    @Test
    public void testGetRegionNoArgWithoutConfiguredHostThrows() {
        LookupDnsRegionProvider provider =
                new LookupDnsRegionProvider(config("masking", "0.0.0.0/16"));
        assertThrows(SdkClientException.class, provider::getRegion);
    }

    @Test
    public void testResolvesEastRegionFromBootstrapIp() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.218.4.7"));
        Map<String, String> txt = Collections.singletonMap("10-218-0-0." + BOOTSTRAP, "us-east-1");

        Region region = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, txt, txtLookups).getRegion();

        assertEquals(Region.US_EAST_1, region);
    }

    @Test
    public void testResolvesWestRegionFromBootstrapIp() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.219.33.12"));
        Map<String, String> txt = Collections.singletonMap("10-219-0-0." + BOOTSTRAP, "us-west-2");

        Region region = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, txt, txtLookups).getRegion();

        assertEquals(Region.US_WEST_2, region);
    }

    @Test
    public void testLowestSortedIpIsChosenForStableLookup() {
        AtomicInteger txtLookups = new AtomicInteger();
        // Two A records in the same /16; the lowest-sorted IP drives the single lookup name.
        Map<String, Set<String>> ips =
                Collections.singletonMap(BOOTSTRAP, Set.of("10.218.9.9", "10.218.4.7"));
        Map<String, String> txt = Collections.singletonMap("10-218-0-0." + BOOTSTRAP, "us-east-1");

        Region region = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, txt, txtLookups).getRegion();

        assertEquals(Region.US_EAST_1, region);
    }

    @Test
    public void testReflectsClusterSwapWhenCachingDisabled() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = new HashMap<>();
        Map<String, String> txt = config(
                "10-218-0-0." + BOOTSTRAP, "us-east-1",
                "10-219-0-0." + BOOTSTRAP, "us-west-2");

        LookupDnsRegionProvider provider = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, txt, txtLookups);

        ips.put(BOOTSTRAP, Set.of("10.218.4.7"));
        assertEquals(Region.US_EAST_1, provider.getRegion());

        // Simulate a cluster swap: bootstrap DNS now points at the west cluster's network.
        ips.put(BOOTSTRAP, Set.of("10.219.1.1"));
        assertEquals(Region.US_WEST_2, provider.getRegion());
    }

    @Test
    public void testUsesHostArgumentWhenNoHostConfigured() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.218.4.7"));
        Map<String, String> txt = Collections.singletonMap("10-218-0-0." + BOOTSTRAP, "us-east-1");

        Region region = provider(
                config("masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, txt, txtLookups).getRegion(BOOTSTRAP);

        assertEquals(Region.US_EAST_1, region);
    }

    @Test
    public void testConfiguredHostOverridesSuppliedHost() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.218.4.7"));
        Map<String, String> txt = Collections.singletonMap("10-218-0-0." + BOOTSTRAP, "us-east-1");

        Region region = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, txt, txtLookups).getRegion("some.other.host.example.com");

        assertEquals(Region.US_EAST_1, region);
    }

    @Test
    public void testHostWithPortIsNormalizedBeforeLookup() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.218.4.7"));
        Map<String, String> txt = Collections.singletonMap("10-218-0-0." + BOOTSTRAP, "us-east-1");

        Region region = provider(
                config("masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, txt, txtLookups).getRegion(BOOTSTRAP + ":9098");

        assertEquals(Region.US_EAST_1, region);
    }

    @Test
    public void testThrowsWhenBootstrapIpUnresolvable() {
        AtomicInteger txtLookups = new AtomicInteger();
        LookupDnsRegionProvider provider = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, Collections.emptyMap(), Collections.emptyMap(), txtLookups);

        SdkClientException ex = assertThrows(SdkClientException.class, provider::getRegion);
        assertEquals(true, ex.getMessage().contains("Could not resolve any IP"));
    }

    @Test
    public void testThrowsWhenTxtRecordMissing() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.218.4.7"));

        LookupDnsRegionProvider provider = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, Collections.emptyMap(), txtLookups);

        SdkClientException ex = assertThrows(SdkClientException.class, provider::getRegion);
        assertEquals(true, ex.getMessage().contains("No region TXT record"));
    }

    @Test
    public void testCachingReusesResolvedRegion() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.218.4.7"));
        Map<String, String> txt = Collections.singletonMap("10-218-0-0." + BOOTSTRAP, "us-east-1");

        LookupDnsRegionProvider provider = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "60"),
                FIXED_CLOCK, ips, txt, txtLookups);

        assertEquals(Region.US_EAST_1, provider.getRegion());
        assertEquals(Region.US_EAST_1, provider.getRegion());
        assertEquals(1, txtLookups.get(), "DNS should only be resolved once due to caching");
    }

    @Test
    public void testRefreshSecondsZeroDisablesCaching() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.218.4.7"));
        Map<String, String> txt = Collections.singletonMap("10-218-0-0." + BOOTSTRAP, "us-east-1");

        LookupDnsRegionProvider provider = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "0"),
                FIXED_CLOCK, ips, txt, txtLookups);

        provider.getRegion();
        provider.getRegion();
        assertEquals(2, txtLookups.get(), "With caching disabled, every call should resolve DNS");
    }

    @Test
    public void testCacheRefreshesAfterExpiryAndPicksUpSwap() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = new HashMap<>();
        ips.put(BOOTSTRAP, Set.of("10.218.4.7"));
        Map<String, String> txt = config(
                "10-218-0-0." + BOOTSTRAP, "us-east-1",
                "10-219-0-0." + BOOTSTRAP, "us-west-2");
        Map<String, String> config = config("host", BOOTSTRAP, "masking", "0.0.0.0/16",
                "refresh.seconds", "30");

        // The clock is captured at construction, so expiry is exercised with a second provider
        // whose clock sits beyond the TTL, mirroring the sibling provider tests.
        AtomicReference<Map<String, Set<String>>> sharedIps = new AtomicReference<>(ips);
        LookupDnsRegionProvider provider = provider(config, FIXED_CLOCK, sharedIps.get(), txt, txtLookups);
        assertEquals(Region.US_EAST_1, provider.getRegion());
        assertEquals(1, txtLookups.get());

        // Within TTL: cached, no new lookup even though DNS "changed".
        ips.put(BOOTSTRAP, Set.of("10.219.1.1"));
        assertEquals(Region.US_EAST_1, provider.getRegion());
        assertEquals(1, txtLookups.get());

        // After TTL: a provider whose clock sits beyond the TTL re-resolves and picks up the swap.
        Clock later = Clock.fixed(FIXED_CLOCK.instant().plusSeconds(60), ZoneId.of("UTC"));
        LookupDnsRegionProvider expired = provider(config, later, ips, txt, txtLookups);
        assertEquals(Region.US_WEST_2, expired.getRegion());
        assertEquals(2, txtLookups.get(), "An expired entry must be resolved again");
    }

    @Test
    public void testInvalidRefreshSecondsFallsBackToDefault() {
        AtomicInteger txtLookups = new AtomicInteger();
        Map<String, Set<String>> ips = Collections.singletonMap(BOOTSTRAP, Set.of("10.218.4.7"));
        Map<String, String> txt = Collections.singletonMap("10-218-0-0." + BOOTSTRAP, "us-east-1");

        // Invalid refresh.seconds falls back to the 60s default, so the second call is cached.
        LookupDnsRegionProvider provider = provider(
                config("host", BOOTSTRAP, "masking", "0.0.0.0/16", "refresh.seconds", "not-a-number"),
                FIXED_CLOCK, ips, txt, txtLookups);

        assertEquals(Region.US_EAST_1, provider.getRegion());
        assertEquals(Region.US_EAST_1, provider.getRegion());
        assertEquals(1, txtLookups.get(), "Default TTL should cache the resolved region");
    }

    @Test
    public void testInvalidMaskingParameterThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new LookupDnsRegionProvider(config("host", BOOTSTRAP, "masking", "0.0.0.0/17")));
    }

    @Test
    public void testRealDnsLookupOfUnresolvableHostThrows() {
        LookupDnsRegionProvider provider = new LookupDnsRegionProvider(
                config("host", "nonexistent.invalid.host.example.invalid", "masking", "0.0.0.0/16"));
        assertThrows(SdkClientException.class, provider::getRegion);
    }
}
