package software.amazon.msk.auth.iam;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkException;

public class CompatibilityHelper {

  /**
   * Convert credentials from v2 to v1
   *
   * @param newCreadientials v2 credentials
   * @return v1 credentials
   */
  public static AWSCredentials toV1Credentials(AwsCredentials newCreadientials) {
    if (newCreadientials instanceof AwsSessionCredentials) {
      return new BasicSessionCredentials(
          newCreadientials.accessKeyId(),
          newCreadientials.secretAccessKey(),
          ((AwsSessionCredentials) newCreadientials).sessionToken()
      );
    } else {
      return new BasicAWSCredentials(
          newCreadientials.accessKeyId(),
          newCreadientials.secretAccessKey()
      );
    }
  }
}
