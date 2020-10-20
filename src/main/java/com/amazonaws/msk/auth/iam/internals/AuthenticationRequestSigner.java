package com.amazonaws.msk.auth.iam.internals;

public interface AuthenticationRequestSigner {
    String sign(AuthenticationRequestParams authenticationRequestParams);
}
