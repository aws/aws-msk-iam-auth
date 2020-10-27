package com.amazonaws.msk.auth.iam;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.Properties;

public class ProducerClientTest {

    public static final String SASL_JAAS_CONFIG_VALUE = "org.apache.kafka.common.security.scram.ScramLoginModule required" +
            " username=\"alice\" password=\"alice-secret\";";

    public static final String SASL_IAM_JAAS_CONFIG_VALUE = "com.amazonaws.msk.auth.iam.IAMLoginModule required;";
    //        " awsProfileName=\"dadada\";";

    @Test
    @Disabled
    public void testProducer() {
        Properties producerProperties = new Properties();
        producerProperties.put("bootstrap.servers", "localhost:9092");
        producerProperties.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producerProperties.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producerProperties.put("sasl.jaas.config", SASL_IAM_JAAS_CONFIG_VALUE);
        producerProperties.put("security.protocol", "SASL_SSL");
 //       producerProperties.put("sasl.mechanism", "SCRAM-SHA-256");
        producerProperties.put("sasl.mechanism", "AWS_MSK_IAM");
        producerProperties.put("sasl.client.callback.handler.class", "com.amazonaws.msk.auth.iam.IAMClientCallbackHandler");
        KafkaProducer<String,String> producer = new KafkaProducer<String, String>(producerProperties);
        producer.send(new ProducerRecord<>("test","keys", "values"));
    }
}