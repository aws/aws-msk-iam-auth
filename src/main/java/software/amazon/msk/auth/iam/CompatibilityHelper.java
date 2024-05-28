package software.amazon.msk.auth.iam;

import software.amazon.awssdk.regions.Region;

public class CompatibilityHelper {

  /**
   * Convert region from v1 to v2
   *
   * @param region v1 region
   * @return v2 region
   */
  public static Region toV2Region(com.amazonaws.regions.Region region) {
    return Region.of(region.getName());
  }
}
