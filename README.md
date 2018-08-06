# Demonstrator Log Generator
This is a simple application for use in the SPECIAL demonstrator. It simulates a line of bussines application by pulling a list of configured repositories from the consent management backend and a list of users from keycloak. It uses these to generate random policies based on the current configuration.

No additional features are planned for this application.

## Options
*   **--rate**: The rate at which the generator outputs events (default: 5s) [$RATE]
*   **--kafka-broker-list**: A comma separated list of brokers used to bootstrap the connection to a kafka cluster. eg: 127.0.0.1, 172.10.50.4 (default: "kafka:9094") [$KAFKA_BROKER_LIST]
*   **--kafka-topic**: The name of the topic on which logs will be produced. (default: "application-logs") [$KAFKA_TOPIC]
*   **--kafka-cert-file**: The path to a certificate file used for client authentication to kafka. [$KAFKA_CERT_FILE]
*   **--kafka-key-file**: The path to a key file used for client authentication to kafka. [$KAFKA_KEY_FILE]
*   **--kafka-ca-file**: The path to a ca file used for client authentication to kafka. [$KAFKA_CA_FILE]
*   **--kafka-verify-ssl**: Set to verify the SSL chain when connecting to kafka [$KAFKA_VERIFY_SSL]
*   **--keycloak-endpoint**: The url where the keycloak server can be reached (default: "http://keycloak:8080/auth") [$KEYCLOAK_ENDPOINT]
*   **--keycloak-user**: The username for the keycloak connection (default: "keycloak") [$KEYCLOAK_USER]
*   **--keycloak-password**: The password for the keycloak connection (default: "keycloak") [$KEYCLOAK_PASSWORD]
*   **--backend-endpoint**: The url where the consent management backend can be reached (default: "http://consent-management-backend") [$BACKEND_ENDPOINT]

## Build
The application is written in golang and uses deps to manage the dependencies. Since the dependencies are vendored into the code tree, building a local binary can be done with a simple:
```bash
go build
```
