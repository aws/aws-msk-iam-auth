package software.amazon.msk.auth.iam.internals.region;

import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class RegionProviderConfigTest {

    /**
     * The JDK's own JNDI DNS defaults, from {@code DEFAULT_INIT_TIMEOUT} and
     * {@code DEFAULT_RETRIES} in {@code com.sun.jndi.dns.DnsContext}.
     */
    private static final long JDK_DEFAULT_INIT_TIMEOUT_MS = 1000;
    private static final int JDK_DEFAULT_RETRIES = 4;

    @Test
    public void testDnsDefaultsMatchTheJdkDefaults() {
        // Route53RegionProvider shipped without setting these JNDI properties at all, so its
        // effective DNS timeout was the JDK's. Lowering either default here would silently shorten
        // that timeout for every existing deployment of that provider, which is a behaviour change
        // disguised as a new feature. These parameters exist so an operator can tighten the bound,
        // not so this library can tighten it on their behalf. If you need a different value, set
        // it in configuration rather than changing these.
        assertEquals(JDK_DEFAULT_INIT_TIMEOUT_MS, RegionProviderConfig.DEFAULT_DNS_TIMEOUT_MS,
                "Default DNS timeout must equal the JDK's DEFAULT_INIT_TIMEOUT");
        assertEquals(JDK_DEFAULT_RETRIES, RegionProviderConfig.DEFAULT_DNS_RETRIES,
                "Default DNS retries must equal the JDK's DEFAULT_RETRIES");
    }

    @Test
    public void testDnsEnvCarriesTheJndiProperties() {
        Hashtable<String, String> env = RegionProviderConfig.dnsEnv(1500, 3);
        assertEquals("com.sun.jndi.dns.DnsContextFactory",
                env.get("java.naming.factory.initial"));
        assertEquals("1500", env.get("com.sun.jndi.dns.timeout.initial"));
        assertEquals("3", env.get("com.sun.jndi.dns.timeout.retries"));
    }

    @Test
    public void testParseLongUsesDefaultWhenAbsentBlankOrUnparseable() {
        Map<String, String> config = new HashMap<>();
        assertEquals(60, RegionProviderConfig.parseLong(config, "k", 60, 0));
        config.put("k", "   ");
        assertEquals(60, RegionProviderConfig.parseLong(config, "k", 60, 0));
        config.put("k", "not-a-number");
        assertEquals(60, RegionProviderConfig.parseLong(config, "k", 60, 0));
        assertEquals(60, RegionProviderConfig.parseLong(null, "k", 60, 0));
    }

    @Test
    public void testParseLongClampsToMinimum() {
        Map<String, String> config = Collections.singletonMap("k", "-5");
        assertEquals(0, RegionProviderConfig.parseLong(config, "k", 60, 0));
        assertEquals(1, RegionProviderConfig.parseLong(config, "k", 60, 1));
    }

    @Test
    public void testParseBoundedIntDoesNotWrapOnOversizedValues() {
        // Parsed as a long and cast, 4294967296 wraps to 0 and 2147483648 wraps negative, which
        // silently defeats the stated minimum.
        assertEquals(Integer.MAX_VALUE,
                RegionProviderConfig.parseBoundedInt(
                        Collections.singletonMap("k", "4294967296"), "k", 3, 1));
        assertEquals(Integer.MAX_VALUE,
                RegionProviderConfig.parseBoundedInt(
                        Collections.singletonMap("k", "2147483648"), "k", 3, 1));
        assertEquals(1,
                RegionProviderConfig.parseBoundedInt(
                        Collections.singletonMap("k", "0"), "k", 3, 1));
        assertEquals(3,
                RegionProviderConfig.parseBoundedInt(Collections.emptyMap(), "k", 3, 1));
    }

    @Test
    public void testValidateRegionIdAcceptsKnownAndRegionShapedIds() {
        assertEquals(Region.US_EAST_1,
                RegionProviderConfig.validateRegionId("us-east-1", "a TXT record"));
        // Global pseudo-regions and the ISO/EUSC partitions are real region ids and must not be
        // rejected by validation.
        assertEquals(Region.AWS_GLOBAL,
                RegionProviderConfig.validateRegionId("aws-global", "a TXT record"));
        assertEquals("us-iso-east-1",
                RegionProviderConfig.validateRegionId("us-iso-east-1", "a TXT record").id());
        // A region launched after this SDK release still resolves.
        assertEquals("ap-southeast-9",
                RegionProviderConfig.validateRegionId("ap-southeast-9", "a TXT record").id());
    }

    @Test
    public void testValidateRegionIdRejectsNonRegionWithSourceInMessage() {
        SdkClientException ex = assertThrows(SdkClientException.class,
                () -> RegionProviderConfig.validateRegionId("not-a-region", "the TXT record at x.y"));
        assertEquals(true, ex.getMessage().contains("not-a-region"));
        assertEquals(true, ex.getMessage().contains("the TXT record at x.y"),
                "The failure must name where the bad value came from");
    }
}
