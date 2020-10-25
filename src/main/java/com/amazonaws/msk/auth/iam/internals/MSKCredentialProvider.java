package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class MSKCredentialProvider implements AWSCredentialsProvider {
    private static final Logger log = LoggerFactory.getLogger(MSKCredentialProvider.class);
    private final Map<String, ?> options;
    private final AWSCredentialsProvider delegate;

    public MSKCredentialProvider(Map<String, ?> options) {
        this.options = options;
        AWSCredentialsProvider profileProvider = new JaasConfigDelegateCredentialProvider(
                new String[]{"awsProfileName"},
                (o) -> Optional.ofNullable(o.get("awsProfileName")).map(p -> {
                    if (log.isDebugEnabled()) {
                        log.debug("Profile {]",p);
                    }
                    return new ProfileCredentialsProvider((String) p);
                }).orElse(null));
        delegate = new AWSCredentialsProviderChain(profileProvider, new DefaultAWSCredentialsProviderChain());
        if (log.isDebugEnabled()) {
            log.debug("Number of options to configure credential provider {}", options.size());
        }
    }

    @Override
    public AWSCredentials getCredentials() {
        return delegate.getCredentials();
    }

    @Override
    public void refresh() {
        delegate.refresh();
    }

    public class JaasConfigDelegateCredentialProvider implements AWSCredentialsProvider {
        private final String[] optionKeys;
        private final ConfigCredentialProviderSuppler supplier;

        public JaasConfigDelegateCredentialProvider(String[] optionKeys,
                ConfigCredentialProviderSuppler supplier) {
            if (log.isDebugEnabled()) {
                log.debug("Optional keys {}", optionKeys);
            }
            this.optionKeys = optionKeys;
            this.supplier = supplier;
        }

        @Override
        public AWSCredentials getCredentials() {
            Optional<String> missingKey = Arrays.stream(optionKeys).filter(k -> !options.containsKey(k)).findFirst();
            if (!missingKey.isPresent()) {
                return supplier.getCredentialProvider(options).getCredentials();
            }
            return null;
        }

        @Override
        public void refresh() {

        }
    }

    @FunctionalInterface
    interface ConfigCredentialProviderSuppler {
        AWSCredentialsProvider getCredentialProvider(Map<String, ?> options);
    }
}
