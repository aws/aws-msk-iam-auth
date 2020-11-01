package com.amazonaws.msk.auth.iam.internals;

import com.amazonaws.auth.internal.SignerConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import java.sql.Date;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class SignedPayloadValidatorUtils {
    private static final String VERSION = "version";
    private static final String HOST = "host";
    private static final String[] requiredKeys = {VERSION,
            HOST,
            SignerConstants.X_AMZ_CREDENTIAL.toLowerCase(),
            SignerConstants.X_AMZ_DATE.toLowerCase(),
            SignerConstants.X_AMZ_SIGNED_HEADER.toLowerCase(),
            SignerConstants.X_AMZ_EXPIRES.toLowerCase(),
            SignerConstants.X_AMZ_SIGNATURE.toLowerCase(),
            SignerConstants.X_AMZ_ALGORITHM.toLowerCase()};

    private static final String ACTION = "action";
    private static final String[] optionalKeys = {
            "x-amz-security-token",
            ACTION,
    };
    private static final SimpleDateFormat dateFormat= new SimpleDateFormat("YYYYMMDD\'T\'HHMMSS\'Z\'");

    private SignedPayloadValidatorUtils() {
    }

    public static void validatePayload(byte[] payload, AuthenticationRequestParams params)
            throws IOException, ParseException {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> propertyMap = (Map<String, String>) mapper.readValue(payload, Map.class);

        assertEquals(9, propertyMap.size());

        //check if all required keys are present and non-empty
        List<String> missingRequiredKeys = Arrays.stream(requiredKeys)
                .filter(k -> propertyMap.get(k) == null || propertyMap.get(k).isEmpty())
                .collect(Collectors.toList());
        assertTrue(missingRequiredKeys.isEmpty());

        // check values for some keys
        assertEquals("2020_10_22", propertyMap.get(VERSION));
        assertEquals(params.getHost(), propertyMap.get(HOST));
        assertEquals("kafka-cluster:Connect", propertyMap.get(ACTION));
        assertEquals("host", propertyMap.get(SignerConstants.X_AMZ_SIGNED_HEADER.toLowerCase()));
        assertEquals(SignerConstants.AWS4_SIGNING_ALGORITHM,
                propertyMap.get(SignerConstants.X_AMZ_ALGORITHM.toLowerCase()));
        assertTrue(dateFormat.parse(propertyMap.get(SignerConstants.X_AMZ_DATE.toLowerCase())).toInstant().isBefore(Instant.now()));
        assertTrue(Integer.parseInt(propertyMap.get(SignerConstants.X_AMZ_EXPIRES.toLowerCase())) <= 900);

    }
}
