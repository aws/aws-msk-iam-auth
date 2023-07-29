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
import lombok.Getter;
import lombok.NonNull;
import software.amazon.msk.auth.iam.IAMClientCallbackHandler;

import javax.security.auth.callback.Callback;

/**
 * This class is used to pass AWSCredentials to the {@link IAMSaslClient}.
 * It is processed by the {@link IAMClientCallbackHandler}.
 * If the callback handler succeeds, it sets the AWSCredentials. If the callback handler fails to load the credentials,
 * it sets the loading exception.
 */
public class AWSCredentialsCallback implements Callback {
    @Getter
    private AWSCredentials awsCredentials = null;
    @Getter
    private Exception loadingException = null;
    @Getter
    private String awsRegion = null;

    public void setAwsCredentials(@NonNull AWSCredentials awsCredentials) {
        this.awsCredentials = awsCredentials;
        this.loadingException = null;
    }

    public void setAWSRegion(String awsRegion) {
        this.awsRegion = awsRegion;
    }

    public void setLoadingException(@NonNull Exception loadingException) {
        this.loadingException = loadingException;
        this.awsCredentials = null;
    }

    public boolean isSuccessful() {
        return awsCredentials != null;
    }
}
