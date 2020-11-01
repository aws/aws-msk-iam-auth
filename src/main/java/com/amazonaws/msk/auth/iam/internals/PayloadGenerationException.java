package com.amazonaws.msk.auth.iam.internals;

import java.io.IOException;

public class PayloadGenerationException extends IOException {
    public PayloadGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
