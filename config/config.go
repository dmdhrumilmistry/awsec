package config

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func NewConfig(region string) (aws.Config, error) {
	if region == "" {
		region = "eu-west-2"
	}

	return config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
}
