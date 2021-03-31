/*
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
package software.amazon.msk.auth.iam;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Properties;

public class ProducerClientTest {
    private static final String SASL_IAM_JAAS_CONFIG_VALUE = "software.amazon.msk.auth.iam.IAMLoginModule required awsProfileName=\"dadada bbbb\";";

    @Test
    @Tag("ignored")
    public void testProducer() {
        Properties producerProperties = new Properties();
        producerProperties.put("bootstrap.servers", "localhost:9092");
        producerProperties.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producerProperties.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producerProperties.put("sasl.jaas.config", SASL_IAM_JAAS_CONFIG_VALUE);
        producerProperties.put("security.protocol", "SASL_SSL");
        producerProperties.put("sasl.mechanism", "AWS_MSK_IAM");
        producerProperties
                .put("sasl.client.callback.handler.class", "software.amazon.msk.auth.iam.IAMClientCallbackHandler");
        KafkaProducer<String, String> producer = new KafkaProducer<String, String>(producerProperties);
        producer.send(new ProducerRecord<>("test", "keys", "values"));
    }
}
