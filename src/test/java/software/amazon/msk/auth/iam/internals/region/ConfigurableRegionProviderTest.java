package software.amazon.msk.auth.iam.internals.region;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConfigurableRegionProviderTest {

    private static final String TEST_PROVIDER_CLASS = TestRegionProvider.class.getName();

    @Test
    public void testGetInstanceWithClassNameOnly() {
        ConfigurableRegionProvider provider = ConfigurableRegionProvider.getInstance(TEST_PROVIDER_CLASS);
        assertNotNull(provider);
        assertTrue(provider instanceof TestRegionProvider);
        TestRegionProvider testProvider = (TestRegionProvider) provider;
        assertTrue(testProvider.getConfig().isEmpty());
    }

    @Test
    public void testGetInstanceWithParams() {
        String descriptor = TEST_PROVIDER_CLASS + "?region=eu-west-1;key2=value2";
        ConfigurableRegionProvider provider = ConfigurableRegionProvider.getInstance(descriptor);
        assertNotNull(provider);
        TestRegionProvider testProvider = (TestRegionProvider) provider;
        assertEquals("eu-west-1", testProvider.getConfig().get("region"));
        assertEquals("value2", testProvider.getConfig().get("key2"));
    }

    @Test
    public void testGetInstanceWithParamNoValue() {
        String descriptor = TEST_PROVIDER_CLASS + "?flagParam";
        ConfigurableRegionProvider provider = ConfigurableRegionProvider.getInstance(descriptor);
        TestRegionProvider testProvider = (TestRegionProvider) provider;
        assertEquals("", testProvider.getConfig().get("flagParam"));
    }

    @Test
    public void testGetInstanceReturnsCorrectRegion() {
        String descriptor = TEST_PROVIDER_CLASS + "?region=ap-southeast-1";
        ConfigurableRegionProvider provider = ConfigurableRegionProvider.getInstance(descriptor);
        assertEquals(Region.AP_SOUTHEAST_1, provider.getRegion("some-host"));
    }

    @Test
    public void testGetInstanceWithWhitespace() {
        String descriptor = "  " + TEST_PROVIDER_CLASS + "  ?  region=us-west-2  ;  key=val  ";
        ConfigurableRegionProvider provider = ConfigurableRegionProvider.getInstance(descriptor);
        TestRegionProvider testProvider = (TestRegionProvider) provider;
        assertEquals("us-west-2", testProvider.getConfig().get("region"));
        assertEquals("val", testProvider.getConfig().get("key"));
    }

    @Test
    public void testGetInstanceWithEmptyParams() {
        String descriptor = TEST_PROVIDER_CLASS + "?";
        ConfigurableRegionProvider provider = ConfigurableRegionProvider.getInstance(descriptor);
        assertNotNull(provider);
        TestRegionProvider testProvider = (TestRegionProvider) provider;
        assertTrue(testProvider.getConfig().isEmpty());
    }

    @Test
    public void testGetInstanceNullDescriptor() {
        assertThrows(IllegalArgumentException.class,
                () -> ConfigurableRegionProvider.getInstance(null));
    }

    @Test
    public void testGetInstanceBlankDescriptor() {
        assertThrows(IllegalArgumentException.class,
                () -> ConfigurableRegionProvider.getInstance("   "));
    }

    @Test
    public void testGetInstanceNonExistentClass() {
        assertThrows(IllegalArgumentException.class,
                () -> ConfigurableRegionProvider.getInstance("com.nonexistent.FakeProvider"));
    }

    @Test
    public void testGetInstanceClassNotImplementingInterface() {
        assertThrows(IllegalArgumentException.class,
                () -> ConfigurableRegionProvider.getInstance(NotARegionProvider.class.getName()));
    }
}
