package com.amazonaws.msk.auth.iam.internals;

interface SignedPayloadGenerator {
    byte[] signedPayload(AuthenticationRequestParams authenticationRequestParams) throws PayloadGenerationException;
}
