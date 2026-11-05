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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;

/**
 * Time-based region cache shared by the DNS-backed region providers, serving the last known good
 * region when a refresh fails.
 *
 * <p>Propagating a refresh failure instead would send the caller to
 * {@code DefaultAwsRegionProviderChain}, which resolves from the environment, profile file or IMDS
 * — none of which can see the DNS indirection these providers exist to follow, so its answer is
 * very likely the wrong region. A transient DNS failure is also far more common than a failover.
 * Each stale serve is logged at WARN so the underlying failure stays visible.
 */
final class CachedRegionResolver {
    private static final Logger log = LoggerFactory.getLogger(CachedRegionResolver.class);

    private final long refreshSeconds;
    private final Clock clock;
    private final Map<String, CachedRegion> cache = new ConcurrentHashMap<>();

    /**
     * @param refreshSeconds how long a resolved region stays fresh. Zero or negative disables
     *                       caching entirely, which also disables stale serving since nothing is
     *                       ever retained.
     * @param clock          clock used for expiry decisions.
     */
    CachedRegionResolver(long refreshSeconds, Clock clock) {
        this.refreshSeconds = refreshSeconds;
        this.clock = clock;
    }

    /**
     * Returns the cached region for {@code key} when it is still fresh, otherwise resolves a new
     * one via {@code resolver}.
     *
     * @param key      cache key, typically the normalized hostname being resolved.
     * @param resolver performs the actual DNS resolution. Only invoked on a miss or after expiry.
     * @return the fresh region, or the last known good region if a refresh failed.
     * @throws RuntimeException the resolver's exception, when there is no previously cached region
     *                          to fall back to.
     */
    Region resolve(String key, Supplier<Region> resolver) {
        if (refreshSeconds <= 0) {
            return resolver.get();
        }

        CachedRegion cached = cache.get(key);
        if (cached != null && !cached.isExpired(clock.instant(), refreshSeconds)) {
            if (log.isDebugEnabled()) {
                log.debug("Returning cached region {} for host: {}", cached.region.id(), key);
            }
            return cached.region;
        }

        try {
            Region region = resolver.get();
            cache.put(key, new CachedRegion(region, clock.instant()));
            return region;
        } catch (RuntimeException e) {
            if (cached != null) {
                log.warn("Failed to refresh the region for host {}; serving the last known good "
                        + "region {} instead. The DNS indirection could not be re-resolved, so this "
                        + "region may be out of date if a failover has occurred.",
                        key, cached.region.id(), e);
                return cached.region;
            }
            throw e;
        }
    }

    private static final class CachedRegion {
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
