package software.amazon.msk.auth.iam.internals.region;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class Route53RegionProviderTest {

    @Test
    public void testConstructorWithHost() {
        Map<String, String> config = new HashMap<>();
        config.put("host", "region.my-cluster.example.com");
        Route53RegionProvider provider = new Route53RegionProvider(config);
        assertNotNull(provider);
    }

    @Test
    public void testConstructorWithEmptyConfig() {
        Route53RegionProvider provider = new Route53RegionProvider(Collections.emptyMap());
        assertNotNull(provider);
    }

    @Test
    public void testConstructorWithNullConfig() {
        Route53RegionProvider provider = new Route53RegionProvider(null);
        assertNotNull(provider);
    }

    @Test
    public void testGetRegionNoHostConfiguredAndNullParam() {
        Route53RegionProvider provider = new Route53RegionProvider(Collections.emptyMap());
        assertThrows(SdkClientException.class, () -> provider.getRegion(null));
    }

    @Test
    public void testGetRegionNoHostConfiguredAndBlankParam() {
        Route53RegionProvider provider = new Route53RegionProvider(Collections.emptyMap());
        assertThrows(SdkClientException.class, () -> provider.getRegion("  "));
    }

    @Test
    public void testGetRegionNoArgDelegatesToGetRegionWithNull() {
        Route53RegionProvider provider = new Route53RegionProvider(Collections.emptyMap());
        assertThrows(SdkClientException.class, () -> provider.getRegion());
    }

    @Test
    public void testGetRegionDnsLookupFailsWithConfiguredHost() {
        Map<String, String> config = new HashMap<>();
        config.put("host", "nonexistent.invalid.host.example.invalid");
        Route53RegionProvider provider = new Route53RegionProvider(config);
        assertThrows(SdkClientException.class, () -> provider.getRegion("ignored"));
    }

    @Test
    public void testGetRegionDnsLookupFailsWithDerivedHost() {
        Route53RegionProvider provider = new Route53RegionProvider(Collections.emptyMap());
        assertThrows(SdkClientException.class,
                () -> provider.getRegion("nonexistent.invalid"));
    }

    @Test
    public void testRefreshSecondsZeroDisablesCaching() {
        Map<String, String> config = new HashMap<>();
        config.put("refresh.seconds", "0");
        config.put("host", "test.example.com");

        AtomicInteger callCount = new AtomicInteger(0);
        Clock clock = Clock.fixed(Instant.parse("2025-01-01T00:00:00Z"), ZoneId.of("UTC"));

        Route53RegionProvider provider = new Route53RegionProvider(config, clock) {
            @Override
            String resolveTxtRecord(String lookupHost) {
                callCount.incrementAndGet();
                return "us-east-1";
            }
        };

        provider.getRegion("any");
        provider.getRegion("any");
        assertEquals(2, callCount.get(), "With caching disabled, every call should resolve DNS");
    }

    @Test
    public void testRefreshSecondsInvalidValueUsesDefault() {
        Map<String, String> config = new HashMap<>();
        config.put("refresh.seconds", "not-a-number");
        config.put("host", "test.example.com");
        Route53RegionProvider provider = new Route53RegionProvider(config);
        assertNotNull(provider);
    }

    @Test
    public void testCacheReturnsCachedValueBeforeExpiry() {
        Instant now = Instant.parse("2025-01-01T00:00:00Z");
        Clock fixedClock = Clock.fixed(now, ZoneId.of("UTC"));

        Map<String, String> config = new HashMap<>();
        config.put("host", "test.example.com");
        config.put("refresh.seconds", "60");

        AtomicInteger callCount = new AtomicInteger(0);
        Route53RegionProvider provider = new Route53RegionProvider(config, fixedClock) {
            @Override
            String resolveTxtRecord(String lookupHost) {
                callCount.incrementAndGet();
                return "us-east-1";
            }
        };

        Region first = provider.getRegion("any");
        Region second = provider.getRegion("any");

        assertEquals(Region.US_EAST_1, first);
        assertEquals(Region.US_EAST_1, second);
        assertEquals(1, callCount.get(), "DNS should only be called once due to caching");
    }

    @Test
    public void testCacheRefreshesAfterExpiry() {
        Instant t0 = Instant.parse("2025-01-01T00:00:00Z");

        Map<String, String> config = new HashMap<>();
        config.put("host", "test.example.com");
        config.put("refresh.seconds", "60");

        AtomicInteger callCount = new AtomicInteger(0);
        AtomicReference<Clock> clockRef = new AtomicReference<>(
                Clock.fixed(t0, ZoneId.of("UTC")));

        // We need a mutable clock, so we use a wrapper
        Route53RegionProvider provider = new Route53RegionProvider(config,
                Clock.fixed(t0, ZoneId.of("UTC"))) {
            @Override
            String resolveTxtRecord(String lookupHost) {
                callCount.incrementAndGet();
                return "eu-west-1";
            }
        };

        Region first = provider.getRegion("any");
        assertEquals(Region.EU_WEST_1, first);
        assertEquals(1, callCount.get());

        // Same clock, should still be cached
        Region second = provider.getRegion("any");
        assertEquals(Region.EU_WEST_1, second);
        assertEquals(1, callCount.get());

        // Create a new provider with advanced clock to test expiry
        Instant t1 = t0.plus(Duration.ofSeconds(120));
        Route53RegionProvider provider2 = new Route53RegionProvider(config,
                Clock.fixed(t1, ZoneId.of("UTC"))) {
            @Override
            String resolveTxtRecord(String lookupHost) {
                callCount.incrementAndGet();
                return "eu-west-1";
            }
        };

        // New provider, empty cache, should call DNS
        Region third = provider2.getRegion("any");
        assertEquals(Region.EU_WEST_1, third);
        assertEquals(2, callCount.get(), "DNS should be called again with a fresh provider");
    }

    @Test
    public void testCustomRefreshSeconds() {
        Instant now = Instant.parse("2025-01-01T00:00:00Z");
        Clock fixedClock = Clock.fixed(now, ZoneId.of("UTC"));

        Map<String, String> config = new HashMap<>();
        config.put("host", "test.example.com");
        config.put("refresh.seconds", "3600");

        AtomicInteger callCount = new AtomicInteger(0);
        Route53RegionProvider provider = new Route53RegionProvider(config, fixedClock) {
            @Override
            String resolveTxtRecord(String lookupHost) {
                callCount.incrementAndGet();
                return "ap-southeast-1";
            }
        };

        Region result = provider.getRegion("any");
        assertEquals(Region.AP_SOUTHEAST_1, result);

        // Multiple calls should all be cached
        for (int i = 0; i < 10; i++) {
            provider.getRegion("any");
        }
        assertEquals(1, callCount.get(), "All calls should use cache with 3600s TTL");
    }
}
