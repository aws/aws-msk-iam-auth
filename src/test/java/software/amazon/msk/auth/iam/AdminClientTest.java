package software.amazon.msk.auth.iam;

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.TopicListing;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

public class AdminClientTest {
    private static final String SASL_IAM_JAAS_CONFIG_VALUE = "software.amazon.msk.auth.iam.IAMLoginModule required awsAccessKeyId=\"\" awsSecretAccessKey=\"\";";

    @Test
//    @Tag("ignored")
    public void testListTopics() {
        Properties properties = new Properties();
        properties.put("bootstrap.servers", "localhost:9092");
        properties.put("sasl.jaas.config", SASL_IAM_JAAS_CONFIG_VALUE);
        properties.put("security.protocol", "SASL_SSL");
        properties.put("sasl.mechanism", "AWS_MSK_IAM");
        properties.put("sasl.client.callback.handler.class", "software.amazon.msk.auth.iam.IAMClientCallbackHandler");

        AdminClient adminClient = AdminClient.create(properties);

        try {
            Collection<TopicListing> topicListingCollection = adminClient.listTopics().listings().get();
            Assertions.assertTrue( 0<  topicListingCollection.size(), "not found topics");
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }

    }
}
