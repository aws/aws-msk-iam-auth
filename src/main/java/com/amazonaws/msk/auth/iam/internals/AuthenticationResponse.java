package com.amazonaws.msk.auth.iam.internals;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

/**
 * This class is used to model the authentication response sent by the broker.
 */
@Getter(onMethod = @__(@JsonIgnore))
@ToString
public class AuthenticationResponse {
    private static final String VERSION_1 = "2020_10_22";
    private static final String VERSION_FIELD_NAME = "version";
    private static final String REQUEST_ID_FIELD_NAME = "request-id";

    @NonNull
    @JsonProperty(VERSION_FIELD_NAME)
    private final String version;

    @JsonProperty(REQUEST_ID_FIELD_NAME)
    @NonNull
    private final String requestId;

    @JsonCreator(mode = JsonCreator.Mode.PROPERTIES)
    public AuthenticationResponse(@JsonProperty(VERSION_FIELD_NAME) String version,
            @JsonProperty(REQUEST_ID_FIELD_NAME) String requestId) {
        if (!VERSION_1.equals(version)) {
            throw new IllegalArgumentException("Invalid version " + version);
        }
        this.version = version;
        this.requestId = requestId;
    }
}
