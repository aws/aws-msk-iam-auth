package software.amazon.msk.auth.iam.internals.utils;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;

public class RegionUtils {

  /**
   * Try to extract the region from the host. If the region is not found, return the default region
   * from the DefaultAwsRegionProviderChain.
   *
   * @param host The host to extract the region from.
   * @return The region extracted from the host.
   */
  public static Region extractRegionFromHost(String host) {
    return Region.regions().stream()
        .filter(region -> host.contains(region.id()))
        .findFirst()
        .orElseGet(() -> DefaultAwsRegionProviderChain.builder().build().getRegion());
  }
}
