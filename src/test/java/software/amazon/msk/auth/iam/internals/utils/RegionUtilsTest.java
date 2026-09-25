package software.amazon.msk.auth.iam.internals.utils;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.msk.auth.iam.internals.region.ConfigurableRegionProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RegionUtilsTest {

    private static final String HOST_WITH_REGION = "b-3.unit-test.abcdef.kafka.us-west-2.amazonaws.com";
    private static final String HOST_NO_REGION = "abcd.efgh.com";

    // Hostnames whose cluster name contains a region id that differs from the endpoint region.
    // The endpoint region (the label before the partition DNS suffix) must always win.
    private static final String HOST_REGION_LIKE_CLUSTER_NAME =
            "b-1.demo-us-west-1-app.abc123.c2.kafka.us-west-2.amazonaws.com";
    private static final String HOST_REGION_LIKE_CLUSTER_NAME_CN =
            "b-1.us-west-1-qa.abcdef.c2.kafka.cn-north-1.amazonaws.com.cn";
    private static final String HOST_REGION_LIKE_CLUSTER_NAME_GOV =
            "b-1.eu-west-1-qa.abcdef.c3.kafka.us-gov-west-1.amazonaws.com";
    private static final String HOST_REGION_LIKE_CLUSTER_NAME_DUALSTACK =
            "b-1.demo-us-west-1-app.abc123.c2.kafka.us-west-2.api.aws";
    private static final String HOST_REGION_LIKE_BOOTSTRAP_SERVERLESS =
            "boot-us-west-1abc.c1.kafka-serverless.us-west-2.amazonaws.com";

    @Test
    public void testExtractRegionFromHostWithRegionInHost() {
        Region region = RegionUtils.extractRegionFromHost(HOST_WITH_REGION);
        assertEquals(Region.US_WEST_2, region);
    }

    @Test
    public void testRegionLikeClusterNameResolvesEndpointRegion() {
        assertEquals(Region.US_WEST_2,
                RegionUtils.extractRegionFromHost(HOST_REGION_LIKE_CLUSTER_NAME));
    }

    @Test
    public void testRegionLikeClusterNameChinaPartitionResolvesEndpointRegion() {
        assertEquals(Region.CN_NORTH_1,
                RegionUtils.extractRegionFromHost(HOST_REGION_LIKE_CLUSTER_NAME_CN));
    }

    @Test
    public void testRegionLikeClusterNameGovCloudResolvesEndpointRegion() {
        assertEquals(Region.US_GOV_WEST_1,
                RegionUtils.extractRegionFromHost(HOST_REGION_LIKE_CLUSTER_NAME_GOV));
    }

    @Test
    public void testRegionLikeClusterNameDualstackResolvesEndpointRegion() {
        assertEquals(Region.US_WEST_2,
                RegionUtils.extractRegionFromHost(HOST_REGION_LIKE_CLUSTER_NAME_DUALSTACK));
    }

    @Test
    public void testRegionLikeBootstrapServerlessResolvesEndpointRegion() {
        assertEquals(Region.US_WEST_2,
                RegionUtils.extractRegionFromHost(HOST_REGION_LIKE_BOOTSTRAP_SERVERLESS));
    }

    @Test
    public void testHostWithPortResolvesEndpointRegion() {
        assertEquals(Region.US_WEST_2,
                RegionUtils.extractRegionFromHost(HOST_REGION_LIKE_CLUSTER_NAME + ":9098"));
    }

    @Test
    public void testUppercaseHostResolvesEndpointRegion() {
        assertEquals(Region.US_WEST_2,
                RegionUtils.extractRegionFromHost(
                        HOST_REGION_LIKE_CLUSTER_NAME.toUpperCase(java.util.Locale.ROOT)));
    }

    @Test
    public void testFullyQualifiedHostWithTrailingRootDotResolvesEndpointRegion() {
        assertEquals(Region.US_WEST_2,
                RegionUtils.extractRegionFromHost(HOST_REGION_LIKE_CLUSTER_NAME + "."));
    }

    @Test
    public void testHostWithSurroundingWhitespaceResolvesEndpointRegion() {
        assertEquals(Region.US_WEST_2,
                RegionUtils.extractRegionFromHost("  " + HOST_REGION_LIKE_CLUSTER_NAME + "  "));
    }

    @Test
    public void testOverlongRegionShapedLabelFallsThroughToProvider() {
        // A DNS label is at most 63 characters (RFC 1035); a longer region-shaped label cannot
        // be a region and must not be minted. The host contains no other region substring, so
        // resolution falls through to the provider chain.
        String overlong = "us-" + new String(new char[60]).replace('\0', 'a') + "-1";
        String host = "b-1.foo.kafka." + overlong + ".amazonaws.com";
        ConfigurableRegionProvider mockProvider = mock(ConfigurableRegionProvider.class);
        when(mockProvider.getRegion(host)).thenReturn(Region.EU_WEST_2);
        assertEquals(Region.EU_WEST_2, RegionUtils.extractRegionFromHost(host, mockProvider));
    }

    @Test
    public void testRegionNewerThanSdkResolvesViaPartitionPattern() {
        // A region launched after this SDK release is absent from Region.regions() but sits in
        // the endpoint's region position and matches the aws partition's region naming pattern.
        // SDK v1 accepted these unconditionally; rejecting them would regress new-region support.
        assertEquals("ap-southeast-9",
                RegionUtils.extractRegionFromHost(
                        "b-1.demo-us-west-1-app.abc123.c2.kafka.ap-southeast-9.amazonaws.com").id());
    }

    @Test
    public void testKnownSuffixWithNonRegionLabelFallsThroughToLegacyScan() {
        // Ends with a known suffix but the pre-suffix label is neither a known region nor
        // region-shaped per any owning partition's pattern. The anchored parse returns empty and
        // the legacy substring scan still resolves the embedded region id. NOTE: the resulting
        // us-west-1 is a legacy misresolution preserved deliberately for backwards compatibility
        // with non-standard hostnames -- it is codified behaviour, not desired behaviour.
        assertEquals(Region.US_WEST_1,
                RegionUtils.extractRegionFromHost("demo-us-west-1-app.kafka.notaregion.amazonaws.com"));
    }

    @Test
    public void testHostThatIsExactlyASuffixFallsThroughToProvider() {
        // A host equal to a bare suffix never anchors (suffix keys carry a leading dot), so
        // resolution falls through to the provider chain without touching the anchored parse.
        ConfigurableRegionProvider mockProvider = mock(ConfigurableRegionProvider.class);
        when(mockProvider.getRegion("amazonaws.com")).thenReturn(Region.EU_CENTRAL_1);
        assertEquals(Region.EU_CENTRAL_1,
                RegionUtils.extractRegionFromHost("amazonaws.com", mockProvider));
    }

    @Test
    public void testEmptyLabelBeforeSuffixFallsThroughToProvider() {
        // A degenerate double-dot host anchors on the suffix with an empty candidate label and
        // must fall through to the provider chain. This pins the fall-through behaviour only:
        // the empty-candidate guard itself is redundant defence (an empty label matches no known
        // region and no partition pattern), so this test cannot detect the guard's removal.
        String host = "foo..amazonaws.com";
        ConfigurableRegionProvider mockProvider = mock(ConfigurableRegionProvider.class);
        when(mockProvider.getRegion(host)).thenReturn(Region.AP_SOUTH_1);
        assertEquals(Region.AP_SOUTH_1, RegionUtils.extractRegionFromHost(host, mockProvider));
    }

    @Test
    public void testUnanchoredHostRetainsLegacySubstringScan() {
        // No AWS endpoint suffix, but a region id appears in the name: the legacy scan must keep
        // resolving it so behaviour for non-AWS hostnames is unchanged.
        assertEquals(Region.US_EAST_1,
                RegionUtils.extractRegionFromHost("myapp.us-east-1.internal.corp"));
    }

    @Test
    public void testExtractRegionFromHostWithRegionInHostIgnoresProvider() {
        ConfigurableRegionProvider mockProvider = mock(ConfigurableRegionProvider.class);
        Region region = RegionUtils.extractRegionFromHost(HOST_WITH_REGION, mockProvider);
        assertEquals(Region.US_WEST_2, region);
        verify(mockProvider, never()).getRegion(Mockito.anyString());
    }

    @Test
    public void testExtractRegionFromHostCustomProviderReturnsRegion() {
        ConfigurableRegionProvider mockProvider = mock(ConfigurableRegionProvider.class);
        when(mockProvider.getRegion(HOST_NO_REGION)).thenReturn(Region.EU_WEST_1);

        Region region = RegionUtils.extractRegionFromHost(HOST_NO_REGION, mockProvider);
        assertEquals(Region.EU_WEST_1, region);
        verify(mockProvider).getRegion(HOST_NO_REGION);
    }

    @Test
    public void testExtractRegionFromHostCustomProviderReturnsNullFallsBackToDefault() {
        ConfigurableRegionProvider mockProvider = mock(ConfigurableRegionProvider.class);
        when(mockProvider.getRegion(HOST_NO_REGION)).thenReturn(null);

        try (MockedStatic<DefaultAwsRegionProviderChain> mockStatic =
                     Mockito.mockStatic(DefaultAwsRegionProviderChain.class)) {
            DefaultAwsRegionProviderChain mockChain = mock(DefaultAwsRegionProviderChain.class);
            when(mockChain.getRegion()).thenReturn(Region.AP_NORTHEAST_1);

            DefaultAwsRegionProviderChain.Builder mockBuilder = mock(DefaultAwsRegionProviderChain.Builder.class);
            when(mockBuilder.build()).thenReturn(mockChain);
            mockStatic.when(DefaultAwsRegionProviderChain::builder).thenReturn(mockBuilder);

            Region region = RegionUtils.extractRegionFromHost(HOST_NO_REGION, mockProvider);
            assertEquals(Region.AP_NORTHEAST_1, region);
        }
    }

    @Test
    public void testExtractRegionFromHostCustomProviderThrowsFallsBackToDefault() {
        ConfigurableRegionProvider mockProvider = mock(ConfigurableRegionProvider.class);
        when(mockProvider.getRegion(HOST_NO_REGION))
                .thenThrow(SdkClientException.create("DNS lookup failed"));

        try (MockedStatic<DefaultAwsRegionProviderChain> mockStatic =
                     Mockito.mockStatic(DefaultAwsRegionProviderChain.class)) {
            DefaultAwsRegionProviderChain mockChain = mock(DefaultAwsRegionProviderChain.class);
            when(mockChain.getRegion()).thenReturn(Region.US_EAST_1);

            DefaultAwsRegionProviderChain.Builder mockBuilder = mock(DefaultAwsRegionProviderChain.Builder.class);
            when(mockBuilder.build()).thenReturn(mockChain);
            mockStatic.when(DefaultAwsRegionProviderChain::builder).thenReturn(mockBuilder);

            Region region = RegionUtils.extractRegionFromHost(HOST_NO_REGION, mockProvider);
            assertEquals(Region.US_EAST_1, region);
        }
    }

    @Test
    public void testExtractRegionFromHostNullProviderFallsBackToDefault() {
        try (MockedStatic<DefaultAwsRegionProviderChain> mockStatic =
                     Mockito.mockStatic(DefaultAwsRegionProviderChain.class)) {
            DefaultAwsRegionProviderChain mockChain = mock(DefaultAwsRegionProviderChain.class);
            when(mockChain.getRegion()).thenReturn(Region.SA_EAST_1);

            DefaultAwsRegionProviderChain.Builder mockBuilder = mock(DefaultAwsRegionProviderChain.Builder.class);
            when(mockBuilder.build()).thenReturn(mockChain);
            mockStatic.when(DefaultAwsRegionProviderChain::builder).thenReturn(mockBuilder);

            Region region = RegionUtils.extractRegionFromHost(HOST_NO_REGION, null);
            assertEquals(Region.SA_EAST_1, region);
        }
    }

    @Test
    public void testExtractRegionFromEndpointHostAnchorsOnPartitionSuffix() {
        assertEquals(Region.US_WEST_2,
                RegionUtils.extractRegionFromEndpointHost(HOST_REGION_LIKE_CLUSTER_NAME).get());
    }

    @Test
    public void testExtractRegionFromEndpointHostEmptyForNonAwsHost() {
        // No partition suffix to anchor on, so the anchored parse yields nothing even though a
        // region id is present. This is what makes it safe for a region provider to call on an
        // arbitrary hostname.
        assertTrue(RegionUtils.extractRegionFromEndpointHost("msk.us-east-1.customer.com").isEmpty());
    }

    @Test
    public void testExtractRegionFromEndpointHostEmptyForNull() {
        assertTrue(RegionUtils.extractRegionFromEndpointHost(null).isEmpty());
    }

    @Test
    public void testExtractRegionFromHostLabelsFindsRegionLabel() {
        assertEquals(Region.US_EAST_1,
                RegionUtils.extractRegionFromHostLabels("msk.us-east-1.customer.com").get());
    }

    @Test
    public void testExtractRegionFromHostLabelsRequiresWholeLabel() {
        // us-west-1 is only part of a longer label, so unlike the legacy substring scan the label
        // scan must not match it.
        assertTrue(RegionUtils.extractRegionFromHostLabels("demo-us-west-1-app.customer.com").isEmpty());
    }

    @Test
    public void testExtractRegionFromHostLabelsNormalizesPortAndCase() {
        assertEquals(Region.US_EAST_1,
                RegionUtils.extractRegionFromHostLabels("MSK.US-EAST-1.CUSTOMER.COM.:9098").get());
    }

    @Test
    public void testExtractRegionFromHostLabelsEmptyForNullAndNoRegion() {
        assertTrue(RegionUtils.extractRegionFromHostLabels(null).isEmpty());
        assertTrue(RegionUtils.extractRegionFromHostLabels("msk.customer.com").isEmpty());
    }

    @Test
    public void testRegionFromLabelKnownRegion() {
        assertEquals(Region.EU_WEST_1, RegionUtils.regionFromLabel("eu-west-1").get());
    }

    @Test
    public void testRegionFromLabelRegionNewerThanSdk() {
        assertEquals("ap-southeast-9", RegionUtils.regionFromLabel("ap-southeast-9").get().id());
    }

    @Test
    public void testRegionFromLabelRejectsNonRegionLabels() {
        assertTrue(RegionUtils.regionFromLabel(null).isEmpty());
        assertTrue(RegionUtils.regionFromLabel("").isEmpty());
        assertTrue(RegionUtils.regionFromLabel("customer").isEmpty());
        assertTrue(RegionUtils.regionFromLabel("demo-us-west-1-app").isEmpty());
        // A dotted string is not a single label and must never be minted as a region.
        assertTrue(RegionUtils.regionFromLabel("msk.us-east-1").isEmpty());
    }

    @Test
    public void testRegionFromLabelRejectsOverlongLabel() {
        // A DNS label is at most 63 characters (RFC 1035).
        assertTrue(RegionUtils.regionFromLabel(
                "us-" + new String(new char[60]).replace('\0', 'a') + "-1").isEmpty());
    }

    @Test
    public void testNormalizeHostStripsPortCaseAndRootDot() {
        assertEquals("msk.customer.com", RegionUtils.normalizeHost("  MSK.Customer.com.:9098  "));
    }
}
