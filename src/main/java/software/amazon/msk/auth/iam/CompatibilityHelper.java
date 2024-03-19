package software.amazon.msk.auth.iam;

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
