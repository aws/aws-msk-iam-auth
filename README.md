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
sasl.jaas.config = software.amazon.msk.auth.iam.IAMLoginModule required awsProfileName="<Credential Profile Name>";
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
    "action": "kafka-cluster:Connect",
    "x-amz-algorithm" : "<algorithm>",
    "x-amz-credential" : "<clientAWSAccessKeyID>/<date in yyyyMMdd format>/<region>/kafka-cluster/aws4_request",
    "x-amz-date" : "<timestamp in yyyyMMdd'T'HHmmss'Z' format>",
    "x-amz-security-token" : "<clientAWSSessionToken if any>",
    "x-amz-signedheaders" : "host",
    "x-amz-expires" : "<expiration in seconds>",
    "x-amz-signature" : "<AWS SigV4 signature computed by the client>"
}
``` 
## Generating the authentication payload
Please note that all the keys in the authentication payload are in lowercase.

The values of the following keys in the authentication payload are fixed for a client:
*  `"version"` currently always has the value `"2020_10_22"`
* `"user-agent"` is a string passed in by the client library to describe the client. The simplest user agent is `"<name
 of client library>"`. However, more details can be added to the user agent as well `"<name of client library
 /<version of client library>/<os and version>/<version of language>"`
* `"action"` always has the value `"kafka-cluster:Connect"`

The values of the remaining keys will be generated by calculating the signature of the authentication payload. The
 signature is calculated by following the rules for generating [presigned urls][PreSigned]. Although, this library
  uses the `AWS4Signer` from the [AWS SDK for Java][AwsSDK] to generate the signature we outline the steps followed
 in the calculation
  

 The inputs to this calculation are 
 1. The AWS Credentials that will be used to sign the authentication payload. This has 3 parts: the client `AWSAccessKeyId`,
  the client `AWSSecretyKeyId` and the optional client `sessionToken`.
 1. The hostname of the kafka broker to which the client wishes to connect.
 1. The AWS region in which the kafka broker exists.
 1. The timestamp when the connection is being made.
 
### Generate a Canonical Request
We start by generating a canonical request with an empty payload based on the inputs.
The canonical request in this case has the following form
```
"GET\n"+
"/\n"+
"<CanonicalQueryString>"+"\n"+
"<CanonicalHeaders>"+"\n"+
"<SignedHeaders>"+"\n"+
"<HashedPayload>"
```

#### Canonical Query String
`"<CanonicalQueryString>"` specifies the authentication parameters as URI-encoded query string parameters. We URI-encode
 query parameter names and values  individually. We also sort the parameters in the canonical query string
  alphabetically by key name. The sorting occurs after encoding. 
The `"<CanonicalQueryString>"` can be calculated by:
```
UriEncode("Action")+"="+UriEncode(""kafka-cluster:Connect")+"&"+
UriEncode("X-Amz-Algorithm")+"="+UriEncode("AWS4-HMAC-SHA256") + "&" +
UriEncode("X-Amz-Credential")+"="+UriEncode(""<clientAWSAccessKeyID>/<timestamp in yyyyMMdd format>/<AWS region>/kafka
-cluster/aws4_request"") + "&" +
UriEncode("X-Amz-Date")+"="+UriEncode("<timestamp in yyyyMMdd'T'HHmmss'Z' format>") + "&" +
UriEncode("X-Amz-Expires")+"="+UriEncode("900") + "&" +
UriEncode("X-Amz-Security-Token")+"="+UriEncode("<client Session Token>") + "&" +
UriEncode("X-Amz-SignedHeaders")+"="+UriEncode("")
```
The exact definition of URIEncode from generating [presigned urls][PreSigned] maybe found [later](#UriEncode)

The query string parameters are in order:
* `"Action"`: Always has the value `"kafka-cluster:Connect"` 
* `"X-Amz-Algorithm"`: Describes the algorithm used to calculate the signature. Currently it is `"AWS4-HMAC-SHA256"`
* `"X-Amz-Credential"`: Contains the access key ID, timestamp in `yyyyMMdd` format, the scope of the credential and
 the constant string `"aws4_request"`. The scope is defined as the AWS region of the kafka broker and the name of the 
 service ("kafa-cluster" in this case). For example if the broker is in `us-west-2` region, the scope is `us-west-2
 /kafka
 -cluster`.This scope will be used again later to calculate the signature in [String To Sign](#string-to-sign) and must
  match the one  used to  calculate the signature. 
* `"X-Amz-Date"`: The date and time format must follow the ISO 8601 standard, and must be formatted with the
 "yyyyMMddTHHmmssZ" format. The date and time must be in UTC.
* `"X-Amz-Expires"` :  Provides the time period, in seconds, for which the generated presigned URL is valid. We
 recommend 900 seconds.
* `"X-Amz-Security-Token"`: The session token if it is specified as part of the AWS Credential. Otherwise this query
 parameter is skipped.
* `"X-Amz-Signedheaders"` is currently always set to `"host"`

#### Canonical Header
`"<CanonicalHeaders>">` is a list of request headers with their values.  Header names must be in lowercase. 
Individual header name and value pairs are separated by the newline character ("\n"). In this case there is just one
 header. So `"<CanonicalHeaders>">` is calculated by:
 ```
"host"+":"+"<broker host name>"+"\n"
```

#### Signed Headers
`"<SignedHeaders>"` is an alphabetically sorted, semicolon-separated list of lowercase request header names. In this
 case there is just one header. So `"<SignedHeaders>"` is calculated by:
 ```
"host"
```

#### Hashed Payload
Since the payload is empty the hashed payload is calculated as
```
Hex(SHA256Hash(""))
```
where 
* `Hex` is a function to do Lowercase base 16 encoding.
* `SHA256Hash` is a Secure Hash Algorithm (SHA) cryptographic hash function.

### String To Sign
From the canonical string, we derive the string that will be used to sign the authentication payload.
The String to Sign is calculated as:
```
"AWS4-HMAC-SHA256" + "\n" +
"<timestamp in yyyyMMdd format>" + "\n" +
"<Scope>" + "\n" +
Hex(SHA256Hash(<CanonicalRequest>))
```

The scope is defined as the AWS region of the kafka broker and the name of the service ("kafa-cluster" in this case). 
For example if the broker is in `us-west-2` region, the scope is `us-west-2/kafka-cluster`


You must sort the header names alphabetically to construct the string, as shown in the following example: 

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
 
### UriEncode
Snipped from the detailed rules for generating [presigned urls][PreSigned].
URI encode every byte. UriEncode() must enforce the following rules:

* URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
* The space character is a reserved character and must be encoded as "%20" (and not as "+").
* Each URI encoded byte is formed by a '%' and the two-digit hexadecimal value of the byte.
* Letters in the hexadecimal value must be uppercase, for example "%1A".
* Encode the forward slash character, '/', everywhere except in the object key name. For example, if the object key
 name is photos/Jan/sample.jpg, the forward slash in the key name is not encoded.

The following is an example UriEncode() function in Java.

```java
public static String UriEncode(CharSequence input, boolean encodeSlash) {
          StringBuilder result = new StringBuilder();
          for (int i = 0; i < input.length(); i++) {
              char ch = input.charAt(i);
              if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '~' || ch == '.') {
                  result.append(ch);
              } else if (ch == '/') {
                  result.append(encodeSlash ? "%2F" : ch);
              } else {
                  result.append(toHexUTF8(ch));
              }
          }
          return result.toString();
      } 
```
   
## Release Notes
### Release 1.0.0
* First version of the Amazon MSK Library for IAM Authentication


See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.


[MSK]: https://aws.amazon.com/msk/
[IAM]: https://aws.amazon.com/iam/
[MSK_IAM]: https://docs.aws.amazon.com/msk/latest/developerguide/iam-access-control.html
[DefaultCreds]: https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html
[CredsFile]: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
[PreSigned]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
[AwsSDK]: https://github.com/aws/aws-sdk-java