package ec2

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func GetAllRegions(cfg aws.Config) []string {
	// Create an EC2 service client
	svc := ec2.NewFromConfig(cfg)

	// Describe regions
	input := &ec2.DescribeRegionsInput{}
	result, err := svc.DescribeRegions(context.TODO(), input)
	if err != nil {
		log.Fatalf("unable to describe regions, %v", err)
		return []string{}
	}

	// Display the results
	regions := make([]string, 0)
	for _, region := range result.Regions {
		regions = append(regions, aws.ToString(region.RegionName))
	}

	return regions
}
