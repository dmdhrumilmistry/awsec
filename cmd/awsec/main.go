package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/dmdhrumilmistry/awsec/networkinterface"
)

func main() {
	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("ap-south-1"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// Create an EC2 service client
	svc := ec2.NewFromConfig(cfg)

	fmt.Println("Listing all public IP addresses of EC2 instances in the region:")
	// Describe network interfaces
	input := &ec2.DescribeNetworkInterfacesInput{}
	result, err := svc.DescribeNetworkInterfaces(context.TODO(), input)
	if err != nil {
		log.Fatalf("unable to describe network interfaces, %v", err)
	}

	// Filter and display the results
	for _, ni := range result.NetworkInterfaces {
		if ni.Association != nil && ni.Association.PublicIp != nil {

			// Collect security group IDs
			var sgIds []string
			for _, sg := range ni.Groups {
				sgIds = append(sgIds, aws.ToString(sg.GroupId))
			}

			if len(sgIds) <= 0 {
				return
			}

			// Describe the security groups
			sgOutputs := networkinterface.DescribeSecurityGroups(svc, sgIds)
			isVulnSg, vulnSGs := networkinterface.GetOpenNetworkInterfaces(sgOutputs)

			if isVulnSg {
				fmt.Printf("ResourceId: %s\n", aws.ToString(ni.NetworkInterfaceId))
				fmt.Printf("ResourceType: AWS::EC2::NetworkInterface\n")
				fmt.Printf("PublicIp: %s\n", aws.ToString(ni.Association.PublicIp))
				fmt.Printf("AvailabilityZone: %s\n", aws.ToString(ni.AvailabilityZone))
				fmt.Printf("AWSRegion: %s\n", cfg.Region)
				fmt.Println()
				fmt.Println("Vulnerable Security Groups:")
				fmt.Println(vulnSGs)
				fmt.Println()
				fmt.Println("--------------------------------------------------")
			}
		}
	}
}
