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
package software.amazon.msk.auth.iam;

import software.amazon.msk.auth.iam.internals.ClassLoaderAwareIAMSaslClientProvider;
import software.amazon.msk.auth.iam.internals.IAMSaslClientProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Map;

/**
 * This Login Module is used to register the {@link IAMSaslClientProvider}.
 * The module is a no-op for other purposes.
 */
public class IAMLoginModule implements LoginModule {
    public static final String MECHANISM = "AWS_MSK_IAM";

    private static final Logger log = LoggerFactory.getLogger(IAMLoginModule.class);

    static {
        ClassLoaderAwareIAMSaslClientProvider.initialize();
        IAMSaslClientProvider.initialize();
    }

    @Override
    public void initialize(Subject subject,
            CallbackHandler callbackHandler,
            Map<String, ?> sharedState,
            Map<String, ?> options) {
        if (log.isDebugEnabled()) {
            log.debug("IAMLoginModule initialized");
        }
    }

    @Override
    public boolean login() throws LoginException {
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return false;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }
}
