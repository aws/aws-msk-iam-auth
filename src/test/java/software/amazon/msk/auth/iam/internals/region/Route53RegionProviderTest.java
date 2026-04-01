package software.amazon.msk.auth.iam.internals.region;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
        // No host configured, getRegion() calls getRegion(null) which should fail
        assertThrows(SdkClientException.class, () -> provider.getRegion());
    }

    @Test
    public void testGetRegionDnsLookupFailsWithConfiguredHost() {
        Map<String, String> config = new HashMap<>();
        config.put("host", "nonexistent.invalid.host.example.invalid");
        Route53RegionProvider provider = new Route53RegionProvider(config);
        // DNS lookup for a non-existent host should throw
        assertThrows(SdkClientException.class, () -> provider.getRegion("ignored"));
    }

    @Test
    public void testGetRegionDnsLookupFailsWithDerivedHost() {
        Route53RegionProvider provider = new Route53RegionProvider(Collections.emptyMap());
        // Will try to resolve "region.nonexistent.invalid" which should fail
        assertThrows(SdkClientException.class,
                () -> provider.getRegion("nonexistent.invalid"));
    }
}
