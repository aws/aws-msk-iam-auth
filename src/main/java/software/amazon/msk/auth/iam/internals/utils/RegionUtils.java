package software.amazon.msk.auth.iam.internals.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.msk.auth.iam.internals.region.ConfigurableRegionProvider;

public class RegionUtils {

  private static final Logger log = LoggerFactory.getLogger(RegionUtils.class);

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
   * Try to extract the region from the host. If the region is not found, use the provided
   * custom region provider. If no custom provider is given, fall back to the
   * DefaultAwsRegionProviderChain. If the custom provider fails or returns null,
   * a warning is logged and the DefaultAwsRegionProviderChain is used as fallback.
   *
   * @param host           The host to extract the region from.
   * @param regionProvider An optional custom region provider to use as fallback. May be null.
   * @return The region extracted from the host or resolved by the provider.
   */
  public static Region extractRegionFromHost(String host, ConfigurableRegionProvider regionProvider) {
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
}
