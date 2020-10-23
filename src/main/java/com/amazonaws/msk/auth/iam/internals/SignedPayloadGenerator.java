package com.amazonaws.msk.auth.iam.internals;

import java.io.IOException;

interface SignedPayloadGenerator {
    byte[] signedPayload(AuthenticationRequestParams authenticationRequestParams) throws IOException;
}
