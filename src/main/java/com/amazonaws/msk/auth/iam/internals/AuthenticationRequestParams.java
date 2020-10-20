package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionMetadata;
import com.amazonaws.regions.RegionMetadataFactory;

import java.time.Instant;

/**
 * This class represents the parameters that will be used to generate the Sigv4 signature
 * as well as the final AuthenticationRequestPayload (except the signature itself) sent to the kafka broker.
 * These are the parameters that will go into this class.
 * Move the string to the payload object.
 * {
 * "version" : "V1", --
 * "host" : "<broker address>", --
 * "credential" : {
 * "accessKeyId" : "<clientAccessKeyID>",
 * "dateScope" : "<date in yyyyMMdd format>",
 * "regionScope" : "<region>",
 * "serviceScope" : "kafka-cluster",
 * "terminator" : "aws4_request",
 * },
 * "signingTimestamp" : "<timestamp in yyyyMMdd'T'HHmmss'Z' format>",
 * "sessionToken" : "<clientSessionToken if any>",
 * "signedHeaders": "host",
 * "signature" : "<V4 signature computed by the client>"
 * }
 **/
public class AuthenticationRequestParams {
    private static final String VERSION_1 = "V1";
    private static final String SIGNED_HEADERS = "host";
    private static final String SERVICE_SCOPE = "kafka-cluster";
    //terminator is SignerConstants.AWS4_TERMINATOR

    private static RegionMetadata regionMetadata = RegionMetadataFactory.create();

    private final String host;
    private final AWSCredentials awsCredentials;
    private final Region region;
    private final Instant signingTimestamp;

    AuthenticationRequestParams(String host,
            AWSCredentials awsCredentials,
            Region region,
            Instant signingTimestamp) {
        this.host = host;
        this.awsCredentials = awsCredentials;
        this.region = region;
        this.signingTimestamp = signingTimestamp;
    }

    public String getServiceScope() {
        return SERVICE_SCOPE;
    }

    public Region getRegion() {
        return region;
    }

    public String getHost() {
        return host;
    }

    public AWSCredentials getAwsCredentials() {
        return awsCredentials;
    }

    public static AuthenticationRequestParams create(String host, AWSCredentials credentials, Instant signingTimestamp)
            throws IllegalArgumentException {
        Region region = regionMetadata.tryGetRegionByEndpointDnsSuffix(host);
        if (region == null) {
            throw new IllegalArgumentException("Host " + host + " does not belong to a valid region.");
        }
        return new AuthenticationRequestParams(host, credentials, region, signingTimestamp);
    }
}
