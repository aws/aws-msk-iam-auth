package software.amazon.msk.auth.iam.internals.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.EndpointTag;
import software.amazon.awssdk.regions.PartitionEndpointKey;
import software.amazon.awssdk.regions.PartitionMetadata;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.msk.auth.iam.internals.region.ConfigurableRegionProvider;

public class RegionUtils {

  private static final Logger log = LoggerFactory.getLogger(RegionUtils.class);

  /**
   * Endpoint DNS suffixes (with a leading dot) for every partition the SDK knows, covering the
   * plain, dualstack and FIPS endpoint variants, each mapped to the region-id patterns of the
   * partitions that own that suffix. Multiple partitions can share a suffix (aws and aws-us-gov
   * both use amazonaws.com), so each suffix carries every owning partition's pattern. Enumerated
   * from the SDK's own partition metadata rather than hardcoded, so new partitions, suffix
   * variants and region naming schemes are picked up by SDK upgrades.
   */
  private static final Map<String, List<Pattern>> ENDPOINT_DNS_SUFFIXES = endpointDnsSuffixes();

  private static final Pattern TRAILING_PORT = Pattern.compile(":\\d+$");

  /**
   * Try to extract the region from the host. If the region is not found, return the default region
   * from the DefaultAwsRegionProviderChain.
   *
   * @param host The host to extract the region from.
   * @return The region extracted from the host.
   */
  public static Region extractRegionFromHost(String host) {
    return extractRegionFromHost(host, null);
  }

  /**
   * Extract the signing region from the host.
   *
   * <p>The host is first parsed against the AWS endpoint structure: when it ends with a known
   * partition DNS suffix, the region is the label immediately before that suffix
   * (for example {@code ...kafka.us-west-2.amazonaws.com} or
   * {@code ...kafka-serverless.us-west-2.amazonaws.com}). Anchoring on the suffix keeps
   * region-like strings elsewhere in the hostname — such as a cluster name containing
   * {@code us-west-1} — from being mistaken for the endpoint region. A label that is not in
   * this SDK's region list is still accepted when it matches the owning partition's region
   * naming pattern, so endpoints in regions launched after this SDK release resolve correctly.
   *
   * <p>If the host does not end with a known suffix, the legacy substring scan is retained for
   * backwards compatibility with non-AWS hostnames. If that also finds nothing, the provided
   * custom region provider is consulted; if no custom provider is given, or it fails or returns
   * null, the DefaultAwsRegionProviderChain is used as the final fallback.
   *
   * @param host           The host to extract the region from.
   * @param regionProvider An optional custom region provider to use as fallback. May be null.
   * @return The region extracted from the host or resolved by the provider.
   */
  public static Region extractRegionFromHost(String host, ConfigurableRegionProvider regionProvider) {
    Optional<Region> anchored = extractRegionFromSuffixAnchoredHost(host);
    if (anchored.isPresent()) {
      return anchored.get();
    }
    return Region.regions().stream()
        .filter(region -> host.contains(region.id()))
        .findFirst()
        .orElseGet(() -> {
          if (regionProvider != null) {
            try {
              log.info("Trying region provider {}", regionProvider.getClass());
              Region region = regionProvider.getRegion(host);

              if (region != null) {
                return region;
              }
              log.warn("Custom region provider returned null for host: {}. "
                  + "Falling back to DefaultAwsRegionProviderChain.", host);
            } catch (Exception e) {
              log.warn("Custom region provider failed for host: {}. "
                  + "Falling back to DefaultAwsRegionProviderChain.", host, e);
            }
          }
          log.info("Falling back to DefaultAwsRegionProviderChain");
          return DefaultAwsRegionProviderChain.builder().build().getRegion();
        });
  }

  /**
   * Anchored parse: if the host ends with a known partition DNS suffix, take the label directly
   * before the suffix. A label in the SDK's region list is returned directly. A label that is
   * not in the list but matches the region naming pattern of a partition owning the matched
   * suffix is accepted as a region newer than this SDK ({@link Region#of} is safe here because
   * the label sits in the endpoint's region position and is partition-validated; using it on an
   * arbitrary unanchored string would mint a Region for anything). Returns empty when no suffix
   * matches or no matched suffix yields a region-shaped label, so the caller falls through to
   * the legacy behaviour.
   */
  private static Optional<Region> extractRegionFromSuffixAnchoredHost(String host) {
    // Normalize to the bare hostname a URL parser would yield: strip surrounding whitespace, a
    // trailing :port and a fully-qualified trailing root dot. DNS names are case-insensitive, so
    // compare in lower case.
    String bareHost = TRAILING_PORT.matcher(host.trim()).replaceFirst("").toLowerCase(Locale.ROOT);
    if (bareHost.endsWith(".")) {
      bareHost = bareHost.substring(0, bareHost.length() - 1);
    }
    for (Map.Entry<String, List<Pattern>> entry : ENDPOINT_DNS_SUFFIXES.entrySet()) {
      if (!bareHost.endsWith(entry.getKey())) {
        continue;
      }
      String head = bareHost.substring(0, bareHost.length() - entry.getKey().length());
      String candidate = head.substring(head.lastIndexOf('.') + 1);
      // A DNS label is at most 63 characters (RFC 1035), so anything longer cannot be a region.
      // The empty check is redundant defence: an empty label matches no region or pattern today,
      // but a pathological future partition pattern could match the empty string.
      if (candidate.isEmpty() || candidate.length() > 63) {
        continue;
      }
      Optional<Region> known = Region.regions().stream()
          .filter(region -> region.id().equals(candidate))
          .findFirst();
      if (known.isPresent()) {
        return known;
      }
      for (Pattern regionPattern : entry.getValue()) {
        if (regionPattern.matcher(candidate).matches()) {
          return Optional.of(Region.of(candidate));
        }
      }
      // Known suffix but the label is not region-shaped; keep trying other suffixes rather
      // than concluding early, in case suffixes ever overlap.
    }
    return Optional.empty();
  }

  private static Map<String, List<Pattern>> endpointDnsSuffixes() {
    // Runs in the static initializer: any escaping exception would surface as
    // ExceptionInInitializerError and permanently fail class loading for the whole auth path.
    // Guard the entire enumeration and fail open to an empty map, which disables the anchored
    // parse and leaves the legacy pre-anchoring behaviour in place.
    try {
      Map<String, Set<String>> suffixToRegexes = new LinkedHashMap<>();
      PartitionEndpointKey[] endpointVariants = {
          PartitionEndpointKey.builder().build(),
          PartitionEndpointKey.builder().tags(EndpointTag.DUALSTACK).build(),
          PartitionEndpointKey.builder().tags(EndpointTag.FIPS).build(),
      };
      for (Region region : Region.regions()) {
        PartitionMetadata partition = PartitionMetadata.of(region);
        for (PartitionEndpointKey endpointVariant : endpointVariants) {
          try {
            String suffix = partition.dnsSuffix(endpointVariant);
            String regionRegex = partition.regionRegex();
            if (suffix != null && !suffix.isEmpty()) {
              // Register the suffix even when the partition has no region pattern: losing the
              // pattern only loses new-region acceptance, but losing the suffix would disable
              // anchoring for the partition entirely and reintroduce the substring-scan defect.
              Set<String> regexes = suffixToRegexes
                  .computeIfAbsent("." + suffix.toLowerCase(Locale.ROOT), k -> new LinkedHashSet<>());
              if (regionRegex != null) {
                regexes.add(regionRegex);
              }
            }
          } catch (RuntimeException e) {
            log.debug("Partition {} has no DNS suffix for endpoint variant {}; skipping.",
                partition.id(), endpointVariant, e);
          }
        }
      }
      Map<String, List<Pattern>> compiled = new LinkedHashMap<>();
      for (Map.Entry<String, Set<String>> entry : suffixToRegexes.entrySet()) {
        List<Pattern> patterns = new ArrayList<>();
        for (String regex : entry.getValue()) {
          // Compile each pattern in isolation so one malformed regex from future SDK metadata
          // only loses new-region acceptance for its own partition; the suffix stays anchored
          // and known-region resolution for it is unaffected.
          try {
            patterns.add(Pattern.compile(regex));
          } catch (RuntimeException e) {
            log.warn("Skipping invalid region pattern {} for suffix {}.", regex, entry.getKey(), e);
          }
        }
        compiled.put(entry.getKey(), Collections.unmodifiableList(patterns));
      }
      return Collections.unmodifiableMap(compiled);
    } catch (RuntimeException e) {
      log.warn("Failed to enumerate endpoint DNS suffixes from SDK partition metadata; "
          + "anchored region extraction is disabled and the legacy behaviour applies.", e);
      return Collections.emptyMap();
    }
  }
}
