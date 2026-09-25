package software.amazon.msk.auth.iam.internals.region;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CnameRegionProviderTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2025-01-01T00:00:00Z"), ZoneId.of("UTC"));

    private static final String ENTRY_HOST = "msk.customer.com";
    private static final String SUFFIX = "customer.com";

    /**
     * Builds a provider whose DNS lookups are served from the supplied chain map instead of real
     * DNS. A host absent from the map has no CNAME record, which is the end of the chain.
     */
    private CnameRegionProvider provider(Map<String, String> config,
                                        Map<String, String> chain,
                                        AtomicInteger lookups) {
        return new CnameRegionProvider(config, FIXED_CLOCK) {
            @Override
            String resolveCname(String lookupHost) {
                lookups.incrementAndGet();
                return chain.get(lookupHost);
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
    public void testConstructorWithEmptyConfig() {
        assertNotNull(new CnameRegionProvider(Collections.emptyMap()));
    }

    @Test
    public void testConstructorWithNullConfig() {
        assertNotNull(new CnameRegionProvider(null));
    }

    @Test
    public void testGetRegionNoHostConfiguredAndNullParam() {
        CnameRegionProvider provider = new CnameRegionProvider(Collections.emptyMap());
        assertThrows(SdkClientException.class, () -> provider.getRegion(null));
    }

    @Test
    public void testGetRegionNoHostConfiguredAndBlankParam() {
        CnameRegionProvider provider = new CnameRegionProvider(Collections.emptyMap());
        assertThrows(SdkClientException.class, () -> provider.getRegion("  "));
    }

    @Test
    public void testGetRegionNoArgWithoutConfiguredHostThrows() {
        CnameRegionProvider provider = new CnameRegionProvider(Collections.emptyMap());
        assertThrows(SdkClientException.class, provider::getRegion);
    }

    @Test
    public void testSingleHopResolvesRegionFromConfiguredSuffix() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "msk.us-east-1.customer.com");

        Region region = provider(config("suffix", SUFFIX), chain, lookups).getRegion(ENTRY_HOST);

        assertEquals(Region.US_EAST_1, region);
        assertEquals(1, lookups.get(), "The walk must stop as soon as a region is found");
    }

    @Test
    public void testSingleHopResolvesRegionWithoutConfiguredSuffix() {
        // With no suffix to anchor on, the label-exact scan still finds the region label.
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "msk.us-east-1.customer.com");

        assertEquals(Region.US_EAST_1,
                provider(Collections.emptyMap(), chain, lookups).getRegion(ENTRY_HOST));
    }

    @Test
    public void testConfiguredSuffixTakesPrecedenceOverRegionLabelElsewhere() {
        // Two region-shaped labels in one name. The suffix anchor pins the region to the label
        // directly before the caller's own domain, so the leading us-east-1 must not win.
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain =
                Collections.singletonMap(ENTRY_HOST, "us-east-1.msk.eu-west-1.customer.com");

        assertEquals(Region.EU_WEST_1,
                provider(config("suffix", SUFFIX), chain, lookups).getRegion(ENTRY_HOST));
    }

    @Test
    public void testChainTerminatingAtAwsEndpointResolvesRegion() {
        // A chain that ends at a genuine AWS name is read by the AWS endpoint parse.
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain =
                Collections.singletonMap(ENTRY_HOST, "nlb-abc123.elb.us-west-2.amazonaws.com");

        assertEquals(Region.US_WEST_2,
                provider(config("suffix", SUFFIX), chain, lookups).getRegion(ENTRY_HOST));
    }

    @Test
    public void testMultipleHopsFollowedUpToMaxHops() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = config(
                ENTRY_HOST, "a.customer.com",
                "a.customer.com", "b.customer.com",
                "b.customer.com", "c.us-west-2.customer.com");

        Region region = provider(config("suffix", SUFFIX, "max.hops", "3"), chain, lookups)
                .getRegion(ENTRY_HOST);

        assertEquals(Region.US_WEST_2, region);
        assertEquals(3, lookups.get());
    }

    @Test
    public void testMaxHopsExhaustedThrows() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = config(
                ENTRY_HOST, "a.customer.com",
                "a.customer.com", "b.customer.com",
                "b.customer.com", "c.us-west-2.customer.com");

        CnameRegionProvider provider =
                provider(config("suffix", SUFFIX, "max.hops", "2"), chain, lookups);

        assertThrows(SdkClientException.class, () -> provider.getRegion(ENTRY_HOST));
        assertEquals(2, lookups.get(), "No more than max.hops lookups may be issued");
    }

    @Test
    public void testEndOfChainWithoutRegionThrows() {
        AtomicInteger lookups = new AtomicInteger();
        // other.customer.com is absent from the chain, so it has no CNAME record.
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "other.customer.com");

        CnameRegionProvider provider = provider(config("suffix", SUFFIX), chain, lookups);

        assertThrows(SdkClientException.class, () -> provider.getRegion(ENTRY_HOST));
        assertEquals(2, lookups.get(), "The walk must stop at the end of the chain, not at max.hops");
    }

    @Test
    public void testCnameLoopIsDetectedAndStopsTheWalk() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = config(
                ENTRY_HOST, "a.customer.com",
                "a.customer.com", ENTRY_HOST);

        CnameRegionProvider provider =
                provider(config("suffix", SUFFIX, "max.hops", "10"), chain, lookups);

        assertThrows(SdkClientException.class, () -> provider.getRegion(ENTRY_HOST));
        assertEquals(2, lookups.get(), "A repeated name must end the walk rather than spin");
    }

    @Test
    public void testRegionMustBeAWholeLabel() {
        // us-east-1 appears only as part of a longer label, so it is not the region. This is the
        // behaviour that distinguishes this provider from a substring scan.
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain =
                Collections.singletonMap(ENTRY_HOST, "msk-us-east-1-primary.customer.com");

        CnameRegionProvider provider = provider(config("suffix", SUFFIX), chain, lookups);

        assertThrows(SdkClientException.class, () -> provider.getRegion(ENTRY_HOST));
    }

    @Test
    public void testRegionNewerThanSdkResolvesFromLabel() {
        // A region launched after this SDK release is absent from Region.regions() but matches the
        // partition's region naming pattern.
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain =
                Collections.singletonMap(ENTRY_HOST, "msk.ap-southeast-9.customer.com");

        assertEquals("ap-southeast-9",
                provider(config("suffix", SUFFIX), chain, lookups).getRegion(ENTRY_HOST).id());
    }

    @Test
    public void testConfiguredHostOverridesSuppliedHost() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain =
                Collections.singletonMap("fixed.customer.com", "fixed.us-west-2.customer.com");

        Region region = provider(config("host", "fixed.customer.com", "suffix", SUFFIX), chain, lookups)
                .getRegion("some.other.host.example.com");

        assertEquals(Region.US_WEST_2, region);
    }

    @Test
    public void testNoArgGetRegionUsesConfiguredHost() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain =
                Collections.singletonMap("fixed.customer.com", "fixed.eu-central-1.customer.com");

        Region region = provider(config("host", "fixed.customer.com", "suffix", SUFFIX), chain, lookups)
                .getRegion();

        assertEquals(Region.EU_CENTRAL_1, region);
    }

    @Test
    public void testHostWithPortIsNormalizedBeforeLookup() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "msk.us-east-1.customer.com");

        assertEquals(Region.US_EAST_1,
                provider(config("suffix", SUFFIX), chain, lookups).getRegion(ENTRY_HOST + ":9098"));
    }

    @Test
    public void testCnameTargetWithTrailingDotAndUppercaseIsNormalized() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain =
                Collections.singletonMap(ENTRY_HOST, "MSK.US-EAST-1.CUSTOMER.COM.");

        assertEquals(Region.US_EAST_1,
                provider(config("suffix", SUFFIX), chain, lookups).getRegion(ENTRY_HOST));
    }

    @Test
    public void testSuffixWithLeadingDotIsAccepted() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "msk.us-east-1.customer.com");

        assertEquals(Region.US_EAST_1,
                provider(config("suffix", "." + SUFFIX), chain, lookups).getRegion(ENTRY_HOST));
    }

    @Test
    public void testCachingReusesResolvedRegion() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "msk.us-east-1.customer.com");

        CnameRegionProvider provider =
                provider(config("suffix", SUFFIX, "refresh.seconds", "60"), chain, lookups);

        assertEquals(Region.US_EAST_1, provider.getRegion(ENTRY_HOST));
        assertEquals(Region.US_EAST_1, provider.getRegion(ENTRY_HOST));
        assertEquals(1, lookups.get(), "DNS should only be walked once due to caching");
    }

    @Test
    public void testRefreshSecondsZeroDisablesCaching() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "msk.us-east-1.customer.com");

        CnameRegionProvider provider =
                provider(config("suffix", SUFFIX, "refresh.seconds", "0"), chain, lookups);

        provider.getRegion(ENTRY_HOST);
        provider.getRegion(ENTRY_HOST);
        assertEquals(2, lookups.get(), "With caching disabled, every call should resolve DNS");
    }

    @Test
    public void testCacheRefreshesAfterExpiry() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "msk.us-east-1.customer.com");
        Map<String, String> config = config("suffix", SUFFIX, "refresh.seconds", "60");

        // The clock is captured at construction, so expiry is exercised with a second provider
        // whose clock sits beyond the TTL.
        CnameRegionProvider provider = provider(config, chain, lookups);
        assertEquals(Region.US_EAST_1, provider.getRegion(ENTRY_HOST));
        assertEquals(1, lookups.get());

        Clock later = Clock.fixed(FIXED_CLOCK.instant().plusSeconds(120), ZoneId.of("UTC"));
        CnameRegionProvider expired = new CnameRegionProvider(config, later) {
            @Override
            String resolveCname(String lookupHost) {
                lookups.incrementAndGet();
                return chain.get(lookupHost);
            }
        };
        assertEquals(Region.US_EAST_1, expired.getRegion(ENTRY_HOST));
        assertEquals(2, lookups.get(), "An expired entry must be walked again");
    }

    @Test
    public void testInvalidNumericConfigFallsBackToDefaults() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = config(
                ENTRY_HOST, "a.customer.com",
                "a.customer.com", "b.customer.com",
                "b.customer.com", "c.us-west-2.customer.com");

        Region region = provider(
                config("suffix", SUFFIX, "max.hops", "not-a-number",
                        "dns.timeout.ms", "", "dns.retries", "x"),
                chain, lookups).getRegion(ENTRY_HOST);

        assertEquals(Region.US_WEST_2, region, "max.hops must fall back to the default of 3");
    }

    @Test
    public void testMaxHopsBelowMinimumIsClampedToOne() {
        AtomicInteger lookups = new AtomicInteger();
        Map<String, String> chain = Collections.singletonMap(ENTRY_HOST, "msk.us-east-1.customer.com");

        Region region = provider(config("suffix", SUFFIX, "max.hops", "0"), chain, lookups)
                .getRegion(ENTRY_HOST);

        assertEquals(Region.US_EAST_1, region);
        assertEquals(1, lookups.get(), "max.hops must never drop below one lookup");
    }

    @Test
    public void testDnsFailurePropagates() {
        CnameRegionProvider provider = new CnameRegionProvider(config("suffix", SUFFIX), FIXED_CLOCK) {
            @Override
            String resolveCname(String lookupHost) {
                throw SdkClientException.create("DNS is down");
            }
        };
        assertThrows(SdkClientException.class, () -> provider.getRegion(ENTRY_HOST));
    }

    @Test
    public void testRealDnsLookupOfUnresolvableHostThrows() {
        CnameRegionProvider provider =
                new CnameRegionProvider(config("dns.timeout.ms", "500", "dns.retries", "0"));
        assertThrows(SdkClientException.class,
                () -> provider.getRegion("nonexistent.invalid.host.example.invalid"));
    }
}
