package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.msk.auth.iam.IAMLoginModule;

import java.security.Provider;
import java.security.Security;

public class IAMSaslClientProvider extends Provider {
    /**
     * Constructs a IAM Sasl Client provider with a fixed name, version number,
     * and information.
     */
    protected IAMSaslClientProvider() {
        super("SASL/IAM Client Provider", 1.0, "SASL/IAM Client Provider for Kafka");
        put("SaslClientFactory." + IAMLoginModule.MECHANISM, IAMSaslClient.IAMSaslClientFactory.class.getName());
    }

    public static void initialize() {
        Security.addProvider(new IAMSaslClientProvider());
    }
}
