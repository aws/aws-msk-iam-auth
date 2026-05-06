package software.amazon.msk.auth.iam.internals.utils;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.msk.auth.iam.internals.region.ConfigurableRegionProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RegionUtilsTest {

    private static final String HOST_WITH_REGION = "b-3.unit-test.abcdef.kafka.us-west-2.amazonaws.com";
    private static final String HOST_NO_REGION = "abcd.efgh.com";

    @Test
    public void testExtractRegionFromHostWithRegionInHost() {
        Region region = RegionUtils.extractRegionFromHost(HOST_WITH_REGION);
        assertEquals(Region.US_WEST_2, region);
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
}
