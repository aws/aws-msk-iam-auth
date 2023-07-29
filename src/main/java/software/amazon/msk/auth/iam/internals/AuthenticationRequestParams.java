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
package software.amazon.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionMetadata;
import com.amazonaws.regions.RegionMetadataFactory;
import com.amazonaws.regions.Regions;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

import java.util.Optional;

/**
 * This class represents the parameters that will be used to generate the Sigv4 signature
 * as well as the final Authentication Payload sent to the kafka broker.
 * The class is versioned so that it can be extended if necessary in the future.
 **/

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
class AuthenticationRequestParams {
    private static final String VERSION_1 = "2020_10_22";
    private static final String SERVICE_SCOPE = "kafka-cluster";
    private static RegionMetadata regionMetadata = RegionMetadataFactory.create();

    @NonNull
    private final String version;
    @NonNull
    private final String host;
    @NonNull
    private final AWSCredentials awsCredentials;
    @NonNull
    private final Region region;
    @NonNull
    private final String userAgent;

    public String getServiceScope() {
        return SERVICE_SCOPE;
    }

    public static AuthenticationRequestParams create(@NonNull String host,
            AWSCredentials credentials,
            @NonNull String userAgent, String awsRegion) throws IllegalArgumentException {
        Region region;
        if(awsRegion != null) { // override region if specified
            region = Region.getRegion(Regions.fromName(awsRegion));
        } else {
            region = Optional.ofNullable(regionMetadata.tryGetRegionByEndpointDnsSuffix(host))
                    .orElseGet(() -> Regions.getCurrentRegion());
        }
        if (region == null) {
            throw new IllegalArgumentException("Host " + host + " does not belong to a valid region.");
        }
        return new AuthenticationRequestParams(VERSION_1, host, credentials, region, userAgent);
    }
}
