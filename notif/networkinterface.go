package notif

import (
	"fmt"
	"log"

	"github.com/dmdhrumilmistry/awsec/networkinterface"
)

func SendNetworkInterfaceNotification(slackWebhook string, vulnsNI []networkinterface.VulnNI) {
	for _, vulnNI := range vulnsNI {
		message := "Vulnerable Network Interface\n"
		message += "Resource Id: " + vulnNI.ResourceId + "\n"
		message += "Public IP: " + vulnNI.PublicIp + "\n"

		for _, vulnNISG := range vulnNI.VulnNISGs {
			message += "============================\n"
			message += "Security Group Id: " + vulnNISG.GroupId + "\n"
			for _, vulnConf := range vulnNISG.VulnConfigs {
				message += fmt.Sprintf("Port: %d CIDR: %s Protocol: %s\n", vulnConf.Port, vulnConf.Cidr, vulnConf.Protocol)
			}
			if SendSlackNotification(slackWebhook, message) {
				log.Printf("Slack Notification Sent for Resource Id: %s\n", vulnNI.ResourceId)
			} else {
				log.Fatalf("Failed to send slack notification for Resource Id: %s\n", vulnNI.ResourceId)
			}
		}

	}

}
