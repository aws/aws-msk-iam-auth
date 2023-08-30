/*
 * Copyright 2012-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package software.amazon.msk.auth.iam.internals;

import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.util.StringUtils;

/**
 * {@link AWSCredentialsProvider} implementation that provides credentials by
 * looking at the <code>aws.accessKeyId</code> and <code>aws.secretKey</code>
 * Java system properties.
 */
public class AwsBasicCredentialsProvider implements AWSCredentialsProvider {

    private final String accessKeyId;
    private final String secretAccessKey;

    public AwsBasicCredentialsProvider(String accessKeyId, String secretAccessKey) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
    }

    @Override
    public AWSCredentials getCredentials() {
        if (StringUtils.isNullOrEmpty(this.accessKeyId) || StringUtils.isNullOrEmpty(this.secretAccessKey)) {
            throw new SdkClientException("Unable to get AWS credentials");
        }
        return new BasicAWSCredentials(this.accessKeyId, this.secretAccessKey);
    }

    @Override
    public void refresh() {
    }

    @Override
    public String toString() {
        return getClass().getSimpleName();
    }
}