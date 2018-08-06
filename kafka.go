package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"

	"github.com/Shopify/sarama"
)

type kafkaConfig struct {
	BrokerList []string
	CertFile   string
	KeyFile    string
	CaFile     string
	VerifySsl  bool
}

func createKafkaProducer(kafkaConfig kafkaConfig) (sarama.SyncProducer, error) {
	if len(kafkaConfig.BrokerList) == 0 {
		return nil, errors.New("A list of initial brokers must be given when using the kafka output")
	}

	config := sarama.NewConfig()
	config.Version = sarama.V1_1_0_0
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 10
	config.Producer.Return.Successes = true
	tlsConfig, err := createTLSConfiguration(kafkaConfig.CertFile, kafkaConfig.KeyFile, kafkaConfig.CaFile, kafkaConfig.VerifySsl)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		config.Net.TLS.Config = tlsConfig
		config.Net.TLS.Enable = true
	}

	return sarama.NewSyncProducer(kafkaConfig.BrokerList, config)
}

func createTLSConfiguration(certFile string, keyFile string, caFile string, verifySsl bool) (*tls.Config, error) {
	var t *tls.Config
	if certFile != "" && keyFile != "" && caFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}

		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		t = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: verifySsl,
		}
	}
	// will be nil by default if nothing is provided
	return t, nil
}
