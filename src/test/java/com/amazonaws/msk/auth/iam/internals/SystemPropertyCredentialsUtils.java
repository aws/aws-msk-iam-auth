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
package com.amazonaws.msk.auth.iam.internals;

public final class SystemPropertyCredentialsUtils {
    private static final String ACCESS_KEY_PROPERTY = "aws.accessKeyId";
    private static final String SECRET_KEY_PROPERTY = "aws.secretKey";

    private SystemPropertyCredentialsUtils() {
    }

    public static void runTestWithSystemPropertyCredentials(Runnable test,
            String accessKeyValue,
            String secretKeyValue) {
        String initialAccessKey = System.getProperty(ACCESS_KEY_PROPERTY);
        String initialSecretKey = System.getProperty(SECRET_KEY_PROPERTY);

        try {
            //Setup test system properties
            System.setProperty(ACCESS_KEY_PROPERTY, accessKeyValue);
            System.setProperty(SECRET_KEY_PROPERTY, secretKeyValue);

            test.run();
        } finally {
            if (initialAccessKey != null) {
                System.setProperty(ACCESS_KEY_PROPERTY, initialAccessKey);
            }
            if (initialSecretKey != null) {
                System.setProperty(SECRET_KEY_PROPERTY, initialSecretKey);
            }
        }
    }
}
