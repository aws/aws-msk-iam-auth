package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.auth.profile.ProfilesConfigFile;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.amazonaws.msk.auth.iam.internals.SystemPropertyCredentialsUtils.runTestWithSystemPropertyCredentials;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MSKCredentialProviderTest {
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
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
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
        }, ACCESS_KEY_VALUE, SECRET_KEY_VALUE);
    }

    @Test
    public void testProfileName() {
        ProfilesConfigFile profilesConfig = getProfilesConfigFile();
        Map<String, String> optionsMap = new HashMap<>();
        optionsMap.put("awsProfileName", "test_profile");
        MSKCredentialProvider provider = new MSKCredentialProvider(optionsMap,
                 Optional.of(new ProfileCredentialsProvider(profilesConfig, "test_profile")));

        AWSCredentials credentials = provider.getCredentials();
        assertEquals("PROFILE_ACCESS_KEY", credentials.getAWSAccessKeyId());
        assertEquals("PROFILE_SECRET_KEY", credentials.getAWSSecretKey());
    }

    private ProfilesConfigFile getProfilesConfigFile() {
        File file = new File(getClass().getClassLoader().getResource("profile_config_file").getFile());
        return new ProfilesConfigFile(file);
    }

}
