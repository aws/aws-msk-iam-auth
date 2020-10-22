package com.amazonaws.msk.auth.iam.internals;

import java.io.IOException;

public interface SignedPayloadGenerator {
    byte [] signedPayload(AuthenticationRequestParams authenticationRequestParams) throws IOException;
}
