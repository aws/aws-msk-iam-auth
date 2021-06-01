package software.amazon.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.profiles.ProfileFile;

/**
 * This credential provider delegates to the v2 ProfileCredentialProvider so that users
 * are able to use Single Sign On credentials and also get more standard credential loading
 * behavior.
 * See https://github.com/aws/aws-sdk-java/issues/803#issuecomment-593530484
 */
public class EnhancedProfileCredentialsProvider implements AWSCredentialsProvider {
    private final ProfileCredentialsProvider delegate;

    public EnhancedProfileCredentialsProvider() {
        delegate = ProfileCredentialsProvider.create();
    }

    public EnhancedProfileCredentialsProvider(String profileName) {
        delegate = ProfileCredentialsProvider.create(profileName);
    }

    public EnhancedProfileCredentialsProvider(ProfileFile profileFile, String profileName) {
        delegate = ProfileCredentialsProvider.builder().profileFile(profileFile).profileName(profileName).build();
    }

    @Override
    public AWSCredentials getCredentials() {
        software.amazon.awssdk.auth.credentials.AwsCredentials credentialsV2 = delegate.resolveCredentials();
        if (credentialsV2 instanceof AwsSessionCredentials) {
            AwsSessionCredentials sessionCredentialsV2 = (AwsSessionCredentials) credentialsV2;
            return new BasicSessionCredentials(sessionCredentialsV2.accessKeyId(),
                    sessionCredentialsV2.secretAccessKey(), sessionCredentialsV2.sessionToken());
        }

        return new BasicAWSCredentials(credentialsV2.accessKeyId(), credentialsV2.secretAccessKey());
    }

    @Override
    public void refresh() {
    }
}
