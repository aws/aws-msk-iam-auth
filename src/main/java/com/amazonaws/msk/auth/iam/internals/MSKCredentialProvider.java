package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

/**
 * This AWS Credential Provider is used to load up AWS Credentials based on options provided on the Jaas config line.
 * As as an example
 * sasl.jaas.config = com.amazonaws.msk.auth.iam.IAMLoginModule required awsProfileName=<profile name>;
 * The currently supported options are:
 * 1. A particular AWS Credential profile: awsProfileName=<profile name>
 * If no options is provided, the DefaultAWSCredentialsProviderChain is used.
 * The DefaultAWSCredentialProviderChain can be pointed to credentials in many different ways:
 * <a href="https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html>Working with AWS Credentials</a>
 * <p>
 * This AWS Credential Provider is meant to be created every time credentials are required and does not refresh.
 * This works for IAMSASLClient since for every authentication a new IAMSaslClient is created resulting in a new
 * MSKCredentialProvider.
 */
public class MSKCredentialProvider implements AWSCredentialsProvider {
    private static final Logger log = LoggerFactory.getLogger(MSKCredentialProvider.class);
    private static final String AWS_PROFILE_NAME_KEY = "awsProfileName";
    private final Map<String, ?> options;
    private final AWSCredentialsProvider delegate;
    private final ProfileCredentialProviderSupplier profileCredentialsProviderSupplier;

    public MSKCredentialProvider(Map<String, ?> options) {
        this(options, (p) -> (new ProfileCredentialsProvider(p)));
    }

    MSKCredentialProvider(Map<String, ?> options,
            ProfileCredentialProviderSupplier profileCredentialsProviderSupplier) {
        this.options = options;
        this.profileCredentialsProviderSupplier = profileCredentialsProviderSupplier;
        delegate = new AWSCredentialsProviderChain(getProfileProvider(), new DefaultAWSCredentialsProviderChain());
        if (log.isDebugEnabled()) {
            log.debug("Number of options to configure credential provider {}", options.size());
        }
    }

    private AWSCredentialsProvider getProfileProvider() {
        return new JaasConfigDelegateCredentialProvider(
                new String[]{AWS_PROFILE_NAME_KEY},
                (o) -> Optional.ofNullable(o.get(AWS_PROFILE_NAME_KEY)).map(p -> {
                    if (log.isDebugEnabled()) {
                        log.debug("Profile name {}", p);
                    }
                    return profileCredentialsProviderSupplier.get((String )p);
                }).orElse(null));
    }

    @Override
    public AWSCredentials getCredentials() {
        return delegate.getCredentials();
    }

    @Override
    public void refresh() {
    }

    public class JaasConfigDelegateCredentialProvider implements AWSCredentialsProvider {
        private final String[] optionKeys;
        private final ConfigCredentialProviderSupplier supplier;

        public JaasConfigDelegateCredentialProvider(String[] optionKeys,
                ConfigCredentialProviderSupplier supplier) {
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
    interface ProfileCredentialProviderSupplier {
        ProfileCredentialsProvider get(String profile);
    }

    @FunctionalInterface
    interface ConfigCredentialProviderSupplier {
        AWSCredentialsProvider getCredentialProvider(Map<String, ?> options);
    }
}
