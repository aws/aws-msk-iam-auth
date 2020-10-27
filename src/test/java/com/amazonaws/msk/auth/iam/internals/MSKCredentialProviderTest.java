package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.auth.profile.ProfilesConfigFile;
import com.amazonaws.msk.auth.iam.IAMClientCallbackHandler;
import org.junit.jupiter.api.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MSKCredentialProviderTest {
    private static final String ACCESS_KEY_PROPERTY = "aws.accessKeyId";
    private static final String SECRET_KEY_PROPERTY = "aws.secretKey";
    private static final String ACCESS_KEY_VALUE = "ACCESS_KEY_VALUE";
    private static final String SECRET_KEY_VALUE = "SECRET_KEY_VALUE";


    /**
     * If no options are passed in it should use the default credentials provider
     * which should pick up the java system properties.
     */
    @Test
    public void testNoOptions() {
        runTestWithSystemPropertyCredentials(() -> {
            MSKCredentialProvider provider = new MSKCredentialProvider(Collections.emptyMap());

            AWSCredentials credentials = provider.getCredentials();

            assertEquals(ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
            assertEquals(SECRET_KEY_VALUE, credentials.getAWSSecretKey());
        });
    }

    /**
     * If a profile name is passed in but there is no profile by that name
     * it should still use the default credential provider.
     */
    @Test
    public void testMissingProfileName() {
        runTestWithSystemPropertyCredentials(() -> {
            Map<String, String> optionsMap = new HashMap<>();
            optionsMap.put("awsProfileName", "MISSING_PROFILE");
            MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap);

            AWSCredentials credentials = provider.getCredentials();

            assertEquals(ACCESS_KEY_VALUE, credentials.getAWSAccessKeyId());
            assertEquals(SECRET_KEY_VALUE, credentials.getAWSSecretKey());
        });
    }

    @Test
    public void testProfileName() {
        ProfilesConfigFile profilesConfig = getProfilesConfigFile();
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsProfileName", "test_profile");
        MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap,
                (p) -> new ProfileCredentialsProvider(profilesConfig, p));

        AWSCredentials credentials = provider.getCredentials();
        assertEquals("PROFILE_ACCESS_KEY", credentials.getAWSAccessKeyId());
        assertEquals("PROFILE_SECRET_KEY", credentials.getAWSSecretKey());
    }

    private ProfilesConfigFile getProfilesConfigFile() {
        File file = new File(getClass().getClassLoader().getResource("profile_config_file").getFile());
        return new ProfilesConfigFile(file);
    }

    private void runTestWithSystemPropertyCredentials(Runnable test) {
        String initialAccessKey = System.getProperty(ACCESS_KEY_PROPERTY);
        String initialSecretKey = System.getProperty(SECRET_KEY_PROPERTY);

        try {
            //Setup test system properties
            System.setProperty(ACCESS_KEY_PROPERTY, ACCESS_KEY_VALUE);
            System.setProperty(SECRET_KEY_PROPERTY, SECRET_KEY_VALUE);

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
