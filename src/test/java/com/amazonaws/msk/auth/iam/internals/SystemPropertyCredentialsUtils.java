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
