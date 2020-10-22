package com.amazonaws.msk.auth.iam.internals;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignedPayloadValidatorUtils {
    public static void validatePayload (byte [] payload) throws IOException {
        String payloadString = new String(payload);
        System.out.println(payloadString);
        ObjectMapper mapper = new ObjectMapper();
        Map propertyMap =  mapper.readValue(payload, Map.class);
        //TODO: no security token
        assertTrue(propertyMap.size() == 9);

    }
}
