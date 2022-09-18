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

import software.amazon.msk.auth.iam.IAMLoginModule;
import software.amazon.msk.auth.iam.internals.IAMSaslClient.ClassLoaderAwareIAMSaslClientFactory;

import java.security.Provider;
import java.security.Security;

public class ClassLoaderAwareIAMSaslClientProvider extends Provider {
    /**
     * Constructs an IAM Sasl Client provider that installs a {@link ClassLoaderAwareIAMSaslClientFactory}.
     */
    protected ClassLoaderAwareIAMSaslClientProvider() {
        super("ClassLoader Aware SASL/IAM Client Provider", 1.0, "SASL/IAM Client Provider for Kafka");
        put("SaslClientFactory." + IAMLoginModule.MECHANISM, ClassLoaderAwareIAMSaslClientFactory.class.getName());
    }

    public static void initialize() {
        Security.addProvider(new ClassLoaderAwareIAMSaslClientProvider());
    }
}
