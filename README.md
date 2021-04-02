## Amazon MSK Library for AWS Identity and Access Management 

## License

This project is licensed under the Apache-2.0 License.

## Introduction
The Amazon MSK Library for AWS Identity and Access Management enables developers to use 
AWS Identity and Access Management (IAM) to connect to their Amazon Managed Streaming for Apache Kafka (Amazon MSK) clusters. 
It allows JVM based Apache Kafka clients to use AWS IAM for authentication and authorization against 
Amazon MSK clusters that have AWS IAM enabled as an authentication mechanism.

This library provides a new Simple Authentication and Security Layer (SASL) mechanism called `AWS_MSK_IAM`. This new 
SASL mechanism can be used by Kafka clients to authenticate against Amazon MSK clusters using AWS IAM.

* [Amazon Managed Streaming for Apache Kafka][MSK]
* [AWS Identity and Access Management][IAM]
* [AWS IAM authentication and authorization for MSK ][MSK_IAM]

## Building from source
After you've downloaded the code from GitHub, you can build it using Gradle. Use this command:
 
 `gradle clean build`

An uber jar containing the library and all its relocated dependencies can also be built. Use this command: 

`gradle clean shadowJar` 

In both cases the generated jar files can be found at: `build/libs/`

## Using the Amazon MSK Library for IAM Authentication
The recommended way to use this library is to consume it from maven central while building a Kafka client application.

  ``` xml
  <dependency>
      <groupId>software.amazon.msk</groupId>
      <artifactId>aws-msk-iam-auth</artifactId>
      <version>1.0.0</version>
  </dependency>
  ```
If you want to use it with a pre-existing Kafka client, you could build the uber jar and place it in the Kafka client's
classpath.

## Configuring a Kafka client to use AWS IAM
You can configure a Kafka client to use AWS IAM for authentication by adding the following properties to the client's 
configuration. 

```properties
# Sets up TLS for encryption and SASL for authN.
security.protocol = SASL_SSL

# Identifies the SASL mechanism to use.
sasl.mechanism = AWS_MSK_IAM

# Binds SASL client implementation.
sasl.jaas.config = software.amazon.msk.auth.iam.IAMLoginModule required;

# Encapsulates constructing a SigV4 signature based on extracted credentials.
# The SASL client bound by "sasl.jaas.config" invokes this class.
sasl.client.callback.handler.class = software.amazon.msk.auth.iam.IAMClientCallbackHandler
```
This configuration finds IAM credentials using the [AWS Default Credentials Provider Chain][DefaultCreds]. To summarize,
the Default Credential Provider Chain looks for credentials in this order:

1. Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. 
1. Java system properties: aws.accessKeyId and aws.secretKey. 
1. Web Identity Token credentials from the environment or container.
1. The default credential profiles file– typically located at ~/.aws/credentials (location can vary per platform), and shared by many of the AWS SDKs and by the AWS CLI.  
You can create a credentials file by using the aws configure command provided by the AWS CLI, or you can create it by editing the file with a text editor. For information about the credentials file format, see [AWS Credentials File Format][CredsFile].
1. It can be used to load credentials from credential profiles other than the default one by setting the environment variable  
AWS_PROFILE to the name of the alternate credential profile. Profiles can be used to load credentials from other sources such as AWS IAM Roles or Single Sign On. See [AWS Credentials File Format][CredsFile] for more details.
1. Amazon ECS container credentials– loaded from the Amazon ECS if the environment variable AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is set. 
1. Instance profile credentials: used on EC2 instances, and delivered through the Amazon EC2 metadata service.

### Specifying an alternate credential profile for a client

If the client wants to specify a particular credential profile as part of the client configuration rather than through 
the environment variable AWS_PROFILE, they can pass in the name of the profile as a client configuration property:
```properties
# Binds SASL client implementation. Uses the specified profile name to look for credentials.
sasl.jaas.config = software.amazon.msk.auth.iam.IAMLoginModule required awsProfileName="<Credential Profile Name
>";
```

## Details
This library introduces a new SASL mechanism called `AWS_MSK_IAM`. The `IAMLoginModule` is used to register the
 `IAMSaslClientProvider` as a `Provider` for the `AWS_MSK_IAM` mechanism. The `IAMSaslClientProvider` is used to
 generate a new `IAMSaslClient` every time a new connection to a Kafka broker is opened or an existing connection
  is re-authenticated.  

The `IAMSaslClient` is used to perform the actual SASL authentication for a client. It evaluates challenges and creates
 responses that can be used to authenticate a Kafka client to a Kafka broker configured with AWS IAM authentication
 . Its initial response contains an authentication payload that includes a signature generated using the client's
  credentials. The `IAMClientCallbackHandler` is used to extract the client credentials that are then used for
   generating the signature.
 
 The authentication payload and the signature are generated by the `AWS4SignedPayloadGenerator` class based on the
  parameters specified in `AuthenticationRequestParams`. The authentication payload consists of a JSON object:
  
  ```json
{
    "version" : "2020_10_22",
    "host" : "<broker address>",
    "user-agent": "<user agent string from the client>",
    "x-amz-algorithm" : "<algorithm>",
    "x-amz-credential" : "<clientAccessKeyID>/<date in yyyyMMdd format>/<region>/kafka-cluster/aws4_request",
    "x-amz-date" : "<timestamp in yyyyMMdd'T'HHmmss'Z' format>",
    "x-amz-security-token" : "<clientSessionToken if any>",
    "x-amz-signedheaders" : "host",
    "x-amz-expires" : "<expiration in seconds>",
    "x-amz-signature" : "<AWS SigV4 signature computed by the client>"
}
``` 
### Generating the authentication payload
We start by generating a simulated `HTTP GET` request. The simulated HTTP request is of the form
```
    GET kafka://<broker-address>?Action=kafka-cluster:Connect HTTP/1.1
```
The http request includes a `host` header that is set to the broker's address.
The simulated HTTP request is now signed following the rules for generating [presigned urls][PreSigned]. This library
uses the `AWS4Signer` from the [AWS SDK for Java][AwsSDK].
For generating the `X-AMZ-CREDENTIAL` query parameter set `AWS-service` to  `kafka-cluster`. 
After the presigned url is generated all its query parameters and their values are converted to a JSON blob as the
 authentication payload. The HTTP headers from the simulated http request are also added to the authentication payload
 as key value pairs. The `version` key with a fixed value of `2020_10_22` and a generated `user-agent` are 
 also added to the authentication payload.
 
   
## Release Notes
### Release 1.0.0
* First version of the Amazon MSK Library for IAM Authentication


See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.


[MSK]: https://aws.amazon.com/msk/
[IAM]: https://aws.amazon.com/iam/
[MSK_IAM]: https://docs.aws.amazon.com/msk/latest/developerguide/kafka_apis_iam.html
[DefaultCreds]: https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html
[CredsFile]: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
[PreSigned]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
[AwsSDK]: https://github.com/aws/aws-sdk-java