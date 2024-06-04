package main

import (
	"flag"
	"log"
	"sync"

	"github.com/dmdhrumilmistry/awsec/config"
	"github.com/dmdhrumilmistry/awsec/ec2"
	"github.com/dmdhrumilmistry/awsec/networkinterface"
	"github.com/dmdhrumilmistry/awsec/notif"
	"github.com/dmdhrumilmistry/awsec/utils"
)

func main() {

	// Parse command line flags
	var slackWebhook string
	var bypassFilePath string
	flag.StringVar(&slackWebhook, "sw", "", "Slack webhook URL")
	flag.StringVar(&bypassFilePath, "bf", "", "Bypass file path")
	flag.Parse()

	// validate flags
	sendNotification := false
	if slackWebhook == "" {
		log.Println("Slack Webhook Not Found!")
	} else {
		sendNotification = true
	}

	config, err := config.NewConfig("eu-west-2")
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	regions := ec2.GetAllRegions(config)

	// get all open network interfaces for all regions
	vulnNIs := []networkinterface.VulnNI{}

	// Iterate over regions
	wg := sync.WaitGroup{}
	mu := sync.Mutex{}
	for _, region := range regions {
		wg.Add(1)

		go func(region string) {
			defer wg.Done()

			// acquire lock to avoid race conditions
			mu.Lock()

			// add open network interfaces to vulnNIs and release lock
			vulnNIs = append(vulnNIs, networkinterface.GetOpenNetworkInterfacesForRegion(region)...)
			mu.Unlock()

			log.Printf("Scanned region: %s\n", region)

		}(region)
	}
	wg.Wait()

	// Get Filter bypass IPs
	bypassIps, err := utils.ReadFileLines(bypassFilePath)
	if err != nil {
		log.Fatalf("Error reading bypass file: %v", err)
	} else {
		vulnNIs = networkinterface.FilterOpenNetworkInterfaces(vulnNIs, bypassIps)
	}

	for _, vulnNI := range vulnNIs {
		log.Println("*** Vulnerable Network Interface ***")
		log.Printf("Resource Id: %s", vulnNI.ResourceId)
		log.Printf("Public IP: %s", vulnNI.PublicIp)
		log.Printf("Availability Zone: %s", vulnNI.AvailabilityZone)
		log.Println()

		for _, vulnNISG := range vulnNI.VulnNISGs {
			log.Println("====== Vulnerable Security Group ======")
			log.Printf("Security Group ID: %s", vulnNISG.GroupId)
			log.Printf("Security Group VPC ID: %s", vulnNISG.VpcId)
			for _, vulnSGConfig := range vulnNISG.VulnConfigs {
				log.Printf("Port: %d\n", vulnSGConfig.Port)
				log.Printf("CIDR: %s\n", vulnSGConfig.Cidr)
				log.Printf("Protocol: %s\n", vulnSGConfig.Protocol)
				log.Println("-------------------------------------")
			}
			log.Println("=====================================")
			log.Println()
		}
	}

	// Send notification
	if sendNotification {
		notif.SendNetworkInterfaceNotification(slackWebhook, vulnNIs)
	}
}
