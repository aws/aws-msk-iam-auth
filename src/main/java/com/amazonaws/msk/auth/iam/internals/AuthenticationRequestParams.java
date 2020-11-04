package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionMetadata;
import com.amazonaws.regions.RegionMetadataFactory;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

import java.time.Instant;
import java.util.Objects;

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

    public String getServiceScope() {
        return SERVICE_SCOPE;
    }

    public static AuthenticationRequestParams create(String host, AWSCredentials credentials)
            throws IllegalArgumentException {
        Objects.nonNull(host);
        final Region region = regionMetadata.tryGetRegionByEndpointDnsSuffix(host);
        if (region == null) {
            throw new IllegalArgumentException("Host " + host + " does not belong to a valid region.");
        }
        return new AuthenticationRequestParams(VERSION_1, host, credentials, region);
    }
}
