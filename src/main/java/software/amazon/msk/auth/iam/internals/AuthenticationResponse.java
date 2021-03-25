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
