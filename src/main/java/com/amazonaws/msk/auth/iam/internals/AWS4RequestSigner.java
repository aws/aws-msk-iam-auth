package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.internal.SignerConstants;
import com.amazonaws.http.HttpMethodName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;

public class AWS4RequestSigner implements AuthenticationRequestSigner {
    private static final Logger log = LoggerFactory.getLogger(AWS4RequestSigner.class);


    public static final String ACTION_KEY = "Action";
    public static final String ACTION_VALUE = "Connect";

    @Override
    public String sign(AuthenticationRequestParams params) {
        final AWS4Signer signer = getConfiguredSigner(params);
        final DefaultRequest request = new DefaultRequest(params.getServiceScope());
        request.setHttpMethod(HttpMethodName.GET);
        try {
            request.setEndpoint(new URI("kafka://" + params.getHost()));
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Failed to parse host URI", e);
        }
        request.addParameter(ACTION_KEY, ACTION_VALUE);
/*        signer.presignRequest(request,params.getAwsCredentials(), null);
        return (String )request.getParameters().get(SignerConstants.X_AMZ_SIGNATURE); */
        signer.sign(request, params.getAwsCredentials());

        return request.toString();
    }

    private AWS4Signer getConfiguredSigner(AuthenticationRequestParams params) {
        //TODO: check if this is too heavy to spin up every time.
        //There are some risks with static since a jvm might talk to different clusters with different creds and regions.
        final AWS4Signer aws4Signer = new AWS4Signer();
        aws4Signer.setServiceName(params.getServiceScope());
        aws4Signer.setRegionName(params.getRegion().getName());
        if (log.isDebugEnabled()) {
            log.debug("Signer configured for {} service and {} region", aws4Signer.getServiceName(),
                    aws4Signer.getRegionName());
        }
        return aws4Signer;
    }
}
