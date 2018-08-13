package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/Shopify/sarama"
	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	"github.com/urfave/cli"
)

// Schema of a SPECIAL log message.
type log struct {
	Timestamp  int64    `json:"timestamp"`
	Process    string   `json:"process"`
	Purpose    string   `json:"purpose"`
	Processing string   `json:"processing"`
	Recipient  string   `json:"recipient"`
	Storage    string   `json:"storage"`
	UserID     string   `json:"userID"`
	Data       []string `json:"data"`
	EventID    string   `json:"eventID"`
}

// Schema of a SPECIAL simplepolicy event
type simplepolicy struct {
	Purpose    string `json:"purposeCollection"`
	Processing string `json:"processingCollection"`
	Recipient  string `json:"recipientCollection"`
	Storage    string `json:"storageCollection"`
	Data       string `json:"dataCollection"`
}

type policy struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	SimplePolicies []simplepolicy `json:"simplePolicies"`
}

// Will run for 5 minutes after which it will exit causing it to reload the user list
// and applications (easier than implementing polling)
func generateLog(users []string, applications []policy, rate time.Duration, ch chan log) {
	amount := int64(5 * time.Minute / rate)
	for i := int64(0); i < amount; i++ {
		application := applications[rand.Intn(len(applications))]
		policy := application.SimplePolicies[rand.Intn(len(application.SimplePolicies))]
		userID := users[rand.Intn(len(users))]
		data := make([]string, 1)
		data[0] = policy.Data
		ch <- log{
			Timestamp:  time.Now().UnixNano() / int64(time.Millisecond),
			Process:    application.Name,
			Purpose:    policy.Purpose,
			Processing: policy.Processing,
			Recipient:  policy.Recipient,
			Storage:    policy.Storage,
			UserID:     userID,
			Data:       data,
			EventID:    uuid.New().String(),
		}
		time.Sleep(rate)
	}
	close(ch)
}

func main() {
	app := cli.NewApp()
	app.Name = "Demo Log Generator"
	app.Usage = "Create a stream of SPECIAL events based on configured users and applications"
	app.ArgsUsage = " "
	app.EnableBashCompletion = true
	app.Version = "2.0.0"
	app.Authors = []cli.Author{
		{
			Name:  "Wouter Dullaert",
			Email: "wouter.dullaert@tenforce.com",
		},
	}
	app.Copyright = "(c) 2018 Tenforce"
	app.Flags = []cli.Flag{
		cli.DurationFlag{
			Name:   "rate",
			Value:  time.Duration(5 * time.Second),
			Usage:  "The `rate` at which the generator outputs events",
			EnvVar: "RATE",
		},
		cli.StringSliceFlag{
			Name:   "kafka-broker-list",
			Value:  &cli.StringSlice{"kafka:9094"},
			Usage:  "A comma separated list of `brokers` used to bootstrap the connection to a kafka cluster. eg: 127.0.0.1, 172.10.50.4",
			EnvVar: "KAFKA_BROKER_LIST",
		},
		cli.StringFlag{
			Name:   "kafka-topic",
			Value:  "application-logs",
			Usage:  "The name of the topic on which logs will be produced.",
			EnvVar: "KAFKA_TOPIC",
		},
		cli.StringFlag{
			Name:   "kafka-cert-file",
			Usage:  "The `path` to a certificate file used for client authentication to kafka.",
			EnvVar: "KAFKA_CERT_FILE",
		},
		cli.StringFlag{
			Name:   "kafka-key-file",
			Usage:  "The `path` to a key file used for client authentication to kafka.",
			EnvVar: "KAFKA_KEY_FILE",
		},
		cli.StringFlag{
			Name:   "kafka-ca-file",
			Usage:  "The `path` to a ca file used for client authentication to kafka.",
			EnvVar: "KAFKA_CA_FILE",
		},
		cli.BoolFlag{
			Name:   "kafka-verify-ssl",
			Usage:  "Set to verify the SSL chain when connecting to kafka",
			EnvVar: "KAFKA_VERIFY_SSL",
		},
		cli.StringFlag{
			Name:   "keycloak-endpoint",
			Value:  "http://keycloak:8080/auth",
			Usage:  "The url where the keycloak server can be reached",
			EnvVar: "KEYCLOAK_ENDPOINT",
		},
		cli.StringFlag{
			Name:   "keycloak-user",
			Value:  "keycloak",
			Usage:  "The username for the keycloak connection",
			EnvVar: "KEYCLOAK_USER",
		},
		cli.StringFlag{
			Name:   "keycloak-password",
			Value:  "keycloak",
			Usage:  "The password for the keycloak connection",
			EnvVar: "KEYCLOAK_PASSWORD",
		},
		cli.StringFlag{
			Name:   "backend-endpoint",
			Value:  "http://consent-management-backend",
			Usage:  "The url where the consent management backend can be reached",
			EnvVar: "BACKEND_ENDPOINT",
		},
	}

	app.Action = func(c *cli.Context) error {
		// Parse out the rate at which events will be produced
		rate := c.Duration("rate")

		// Parse out the kafka topic
		kafkaTopic := c.String("kafka-topic")

		var err error

		// Get the list of users from keycloak
		keycloakEndpoint := c.String("keycloak-endpoint")
		keycloakUser := c.String("keycloak-user")
		keycloakPassword := c.String("keycloak-password")

		const maxDuration = time.Duration(1 * time.Minute)
		b := backoff.NewExponentialBackOff()
		b.MaxElapsedTime = maxDuration

		fmt.Println("[INFO] Authenticating against keycloak")
		var token string
		operation := func() error {
			token, err = authenticate(keycloakEndpoint, keycloakUser, keycloakPassword)
			return err
		}
		err = backoff.Retry(operation, b)
		if err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
		fmt.Println("[INFO] Sucessfully authenticated against keycloak")

		fmt.Println("[INFO] Retrieving user list")
		var userList []string
		operation = func() error {
			userList, err = getUserList(keycloakEndpoint, token)
			return err
		}
		err = backoff.Retry(operation, b)
		if err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
		fmt.Printf("[INFO] Successfully retrieved user list: %s\n", userList)

		// Get the list of application policies from the backend
		fmt.Println("[INFO] Retrieving application policies")
		backendEndpoint := c.String("backend-endpoint")
		var applications []policy
		operation = func() error {
			applications, err = getApplicationPolicies(backendEndpoint, token)
			return err
		}
		err = backoff.Retry(operation, b)
		if err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
		fmt.Printf("[INFO] Successfully retrieved application list: %s\n", applications)

		// Connect to kafka
		fmt.Println("[INFO] Connecting to kafka")
		kafkaConfig := kafkaConfig{
			BrokerList: c.StringSlice("kafka-broker-list"),
			CertFile:   c.String("kafka-cert-file"),
			KeyFile:    c.String("kafka-key-file"),
			CaFile:     c.String("kafka-ca-file"),
			VerifySsl:  c.Bool("kafka-verify-ssl"),
		}
		var kafkaProducer sarama.SyncProducer
		operation = func() error {
			kafkaProducer, err = createKafkaProducer(kafkaConfig)
			return err
		}
		err = backoff.Retry(operation, b)
		if err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
		defer kafkaProducer.Close()
		fmt.Printf("[INFO] Successfully connected to kafka cluster at %s\n", c.StringSlice("kafka-broker-list"))

		// Produce stuff!
		ch := make(chan log)
		go generateLog(userList, applications, rate, ch)

		for log := range ch {
			b, err := json.Marshal(log)
			if err != nil {
				return cli.NewExitError(err.Error(), 1)
			}
			_, _, err = kafkaProducer.SendMessage(&sarama.ProducerMessage{
				Topic: kafkaTopic,
				Value: sarama.StringEncoder(b),
			})
			if err != nil {
				return cli.NewExitError(err.Error(), 1)
			}
		}

		return nil
	}

	app.Run(os.Args)
}
