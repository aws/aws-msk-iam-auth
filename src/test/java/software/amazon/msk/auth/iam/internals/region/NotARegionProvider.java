package software.amazon.msk.auth.iam.internals.region;

import java.util.Map;

/**
 * A class that does NOT implement ConfigurableRegionProvider, used for negative tests.
 */
public class NotARegionProvider {
    public NotARegionProvider(Map<String, String> config) {
    }
}
