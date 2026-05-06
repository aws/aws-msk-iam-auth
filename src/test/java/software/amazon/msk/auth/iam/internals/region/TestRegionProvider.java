package software.amazon.msk.auth.iam.internals.region;

import java.util.Map;

import software.amazon.awssdk.regions.Region;

/**
 * A simple test implementation of {@link ConfigurableRegionProvider} used in unit tests.
 */
public class TestRegionProvider implements ConfigurableRegionProvider {
    private final Map<String, String> config;

    public TestRegionProvider(Map<String, String> config) {
        this.config = config;
    }

    public Map<String, String> getConfig() {
        return config;
    }

    @Override
    public Region getRegion(String host) {
        String regionId = config.get("region");
        return regionId != null ? Region.of(regionId) : Region.US_EAST_1;
    }

    @Override
    public Region getRegion() {
        return getRegion(null);
    }
}
