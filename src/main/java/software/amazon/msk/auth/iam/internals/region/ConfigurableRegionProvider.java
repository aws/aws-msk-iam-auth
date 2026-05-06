/*
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
package software.amazon.msk.auth.iam.internals.region;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.AwsRegionProvider;

/**
 * Extension of {@link AwsRegionProvider} that supports configuration via a
 * parameter map. Implementations must provide a constructor that accepts a
 * {@code Map<String, String>} of configuration parameters.
 *
 * <p>The static {@link #getInstance(String)} factory parses a descriptor string
 * in the format {@code className?param1=value1;param2=value2} and instantiates
 * the target class by passing the parsed parameters to its map constructor.</p>
 */
public interface ConfigurableRegionProvider extends AwsRegionProvider {

    /**
     * Resolve the region using a provided host as context.
     *
     * @param host the host to use for region resolution
     * @return the resolved AWS {@link Region}
     */
    Region getRegion(String host);

    /**
     * Parse a descriptor string and instantiate the corresponding
     * {@link ConfigurableRegionProvider}.
     *
     * <p>Descriptor format: {@code fully.qualified.ClassName?key1=val1;key2=val2}
     * <br>The query-string portion is optional. When omitted an empty map is
     * passed to the constructor.</p>
     *
     * @param descriptor class name with optional parameters
     * @return a configured instance of the provider
     * @throws IllegalArgumentException if the descriptor is null/blank or
     *         the class cannot be instantiated
     */
    static ConfigurableRegionProvider getInstance(String descriptor) {
        if (descriptor == null || descriptor.isBlank()) {
            throw new IllegalArgumentException("Region provider descriptor must not be null or blank");
        }

        String className;
        Map<String, String> params;

        int queryIdx = descriptor.indexOf('?');
        if (queryIdx < 0) {
            className = descriptor.trim();
            params = Collections.emptyMap();
        } else {
            className = descriptor.substring(0, queryIdx).trim();
            params = parseParams(descriptor.substring(queryIdx + 1));
        }

        try {
            Class<?> clazz = Class.forName(className);
            return (ConfigurableRegionProvider) clazz
                    .getDeclaredConstructor(Map.class)
                    .newInstance(params);
        } catch (ClassCastException e) {
            throw new IllegalArgumentException(
                    className + " does not implement ConfigurableRegionProvider", e);
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Failed to instantiate ConfigurableRegionProvider: " + className, e);
        }
    }

    private static Map<String, String> parseParams(String queryString) {
        Map<String, String> params = new LinkedHashMap<>();
        if (queryString == null || queryString.isBlank()) {
            return params;
        }
        for (String pair : queryString.split(";")) {
            String trimmed = pair.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eqIdx = trimmed.indexOf('=');
            if (eqIdx < 0) {
                params.put(trimmed, "");
            } else {
                params.put(trimmed.substring(0, eqIdx).trim(),
                           trimmed.substring(eqIdx + 1).trim());
            }
        }
        return params;
    }
}
