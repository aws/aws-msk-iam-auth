package software.amazon.msk.auth.iam.internals.region;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CachedRegionResolverTest {

    private static final Instant T0 = Instant.parse("2025-01-01T00:00:00Z");

    /** A clock whose instant can be advanced, so one resolver instance can cross its own TTL. */
    private static final class MovableClock extends Clock {
        private final AtomicReference<Instant> now = new AtomicReference<>(T0);

        void advanceSeconds(long seconds) {
            now.updateAndGet(i -> i.plusSeconds(seconds));
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }

    @Test
    public void testResolvesOnMissAndCachesWithinTtl() {
        AtomicInteger calls = new AtomicInteger();
        CachedRegionResolver resolver = new CachedRegionResolver(60, new MovableClock());

        assertEquals(Region.US_EAST_1, resolver.resolve("host", () -> {
            calls.incrementAndGet();
            return Region.US_EAST_1;
        }));
        assertEquals(Region.US_EAST_1, resolver.resolve("host", () -> {
            calls.incrementAndGet();
            return Region.US_EAST_1;
        }));
        assertEquals(1, calls.get(), "A fresh entry must not be re-resolved");
    }

    @Test
    public void testReResolvesAfterTtlExpires() {
        AtomicInteger calls = new AtomicInteger();
        MovableClock clock = new MovableClock();
        CachedRegionResolver resolver = new CachedRegionResolver(60, clock);
        AtomicReference<Region> current = new AtomicReference<>(Region.US_EAST_1);

        assertEquals(Region.US_EAST_1, resolver.resolve("host", () -> {
            calls.incrementAndGet();
            return current.get();
        }));

        current.set(Region.US_WEST_2);
        clock.advanceSeconds(120);

        assertEquals(Region.US_WEST_2, resolver.resolve("host", () -> {
            calls.incrementAndGet();
            return current.get();
        }), "An expired entry must pick up the new region");
        assertEquals(2, calls.get());
    }

    @Test
    public void testServesStaleRegionWhenRefreshFails() {
        MovableClock clock = new MovableClock();
        CachedRegionResolver resolver = new CachedRegionResolver(60, clock);

        assertEquals(Region.US_EAST_1, resolver.resolve("host", () -> Region.US_EAST_1));

        clock.advanceSeconds(120);

        // DNS is now failing. Propagating would send the caller to the default provider chain,
        // which knows nothing about the DNS indirection, so the last known good region is served.
        Region region = resolver.resolve("host", () -> {
            throw SdkClientException.create("DNS is down");
        });
        assertEquals(Region.US_EAST_1, region);
    }

    @Test
    public void testKeepsServingStaleRegionUntilRefreshSucceeds() {
        MovableClock clock = new MovableClock();
        CachedRegionResolver resolver = new CachedRegionResolver(60, clock);
        assertEquals(Region.US_EAST_1, resolver.resolve("host", () -> Region.US_EAST_1));

        clock.advanceSeconds(120);
        assertEquals(Region.US_EAST_1, resolver.resolve("host", () -> {
            throw SdkClientException.create("still down");
        }));

        // The stale entry must not have displaced the cached value, so the next failure is also
        // covered, and recovery is picked up as soon as DNS answers again.
        clock.advanceSeconds(120);
        assertEquals(Region.US_EAST_1, resolver.resolve("host", () -> {
            throw SdkClientException.create("still down");
        }));

        clock.advanceSeconds(120);
        assertEquals(Region.EU_WEST_1, resolver.resolve("host", () -> Region.EU_WEST_1),
                "Once DNS recovers the new region must be adopted");
    }

    @Test
    public void testPropagatesFailureWhenNothingCached() {
        CachedRegionResolver resolver = new CachedRegionResolver(60, new MovableClock());
        assertThrows(SdkClientException.class, () -> resolver.resolve("host", () -> {
            throw SdkClientException.create("DNS is down");
        }));
    }

    @Test
    public void testStaleServingIsPerKey() {
        MovableClock clock = new MovableClock();
        CachedRegionResolver resolver = new CachedRegionResolver(60, clock);
        resolver.resolve("east", () -> Region.US_EAST_1);

        clock.advanceSeconds(120);

        assertEquals(Region.US_EAST_1, resolver.resolve("east", () -> {
            throw SdkClientException.create("down");
        }));
        // A host that was never resolved has no last known good value to serve.
        assertThrows(SdkClientException.class, () -> resolver.resolve("west", () -> {
            throw SdkClientException.create("down");
        }));
    }

    @Test
    public void testCachingDisabledResolvesEveryCallAndNeverServesStale() {
        AtomicInteger calls = new AtomicInteger();
        CachedRegionResolver resolver = new CachedRegionResolver(0, new MovableClock());

        resolver.resolve("host", () -> {
            calls.incrementAndGet();
            return Region.US_EAST_1;
        });
        resolver.resolve("host", () -> {
            calls.incrementAndGet();
            return Region.US_EAST_1;
        });
        assertEquals(2, calls.get(), "With caching disabled every call must resolve");

        // Nothing is retained, so there is no stale value to fall back on.
        assertThrows(SdkClientException.class, () -> resolver.resolve("host", () -> {
            throw SdkClientException.create("DNS is down");
        }));
    }
}
