package software.amazon.msk.auth.iam;

import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkException;

public class CompatibilityHelper {

  /**
   * Convert an exception to an SdkException
   *
   * @param e Exception to convert
   * @return SdkException
   */
  public static SdkException toSdkException(Exception e) {
    if (e instanceof com.amazonaws.SdkClientException) {
      return SdkClientException.create(e.getMessage(), e.getCause());
    } else if (e instanceof SdkException) {
      return (SdkException) e;
    } else {
      return SdkException.create(e.getMessage(), e);
    }
  }
}
