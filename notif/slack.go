package notif

import (
	"encoding/json"
	"log"

	"github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/valyala/fasthttp"
)

func SendSlackNotification(webhookUrl, message string) bool {
	if webhookUrl == "" {
		return false
	}

	// Create a new FHClient without any rate limit
	fhc := client.NewFHClient(&fasthttp.Client{})

	//
	jsonBody := map[string]string{
		"text": message,
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	jsonBodyBytes, err := json.Marshal(jsonBody)
	if err != nil {
		log.Fatalf("failed to marshal json data: %s", err.Error())
		return false
	}

	resp, err := client.Post(fhc, webhookUrl, nil, headers, jsonBodyBytes)
	if err != nil {
		log.Fatalf("failed to send slack notification: %s", err.Error())
		return false
	}

	if resp.StatusCode != fasthttp.StatusOK {
		log.Fatalf("failed to send slack notification: %s", string(resp.Body))
		return false
	}

	return true
}
