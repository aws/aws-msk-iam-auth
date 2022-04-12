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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringJoiner;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

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

    static Set<String> getClassNamesFromJarFile(File givenFile) throws IOException {
        Set<String> classNames = new HashSet<>();
        try (JarFile jarFile = new JarFile(givenFile)) {
            Enumeration<JarEntry> e = jarFile.entries();
            while (e.hasMoreElements()) {
                JarEntry jarEntry = e.nextElement();
                if (jarEntry.getName().endsWith(".class")) {
                    String className = jarEntry.getName()
                            .replace("/", ".")
                            .replace(".class", "");
                    classNames.add(className);
                }
            }
            return classNames;
        }
    }

    static Set<Class> getClassesFromJarFile(File jarFile) throws IOException, ClassNotFoundException {
        Set<String> classNames = getClassNamesFromJarFile(jarFile);
        Set<Class> classes = new HashSet<>(classNames.size());
        try (URLClassLoader cl = URLClassLoader.newInstance(
                new URL[] { new URL("jar:file:" + jarFile + "!/") })) {
            for (String name : classNames) {
                if (name.contains("amazon.msk.auth.iam")) {
                    try {
                        Class clazz = cl.loadClass(name); // Load the class by its name
                        classes.add(clazz);
                    } catch (Throwable ce) {
                        System.out.println(ce);
                    }
                }
            }
        }
        return classes;
    }

    @Test
    public void testParent() throws IOException, ClassNotFoundException {
        Set<Class> classes = getClassesFromJarFile(new File("/Volumes/workplace/github/aws-msk-iam-auth/aws-msk-iam-auth/aws-msk-iam-auth-relocated-source-kafka.jar"));
        classes.stream().filter(c->c.getInterfaces().length > 0).map(c -> c.getName()+" "+c.getCanonicalName()+" ["+
                Arrays.stream(c.getInterfaces()).map(i -> i.getCanonicalName()).collect(Collectors.joining())+" ] ").forEach(System.out::println);
    }
}
