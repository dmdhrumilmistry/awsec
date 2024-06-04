package networkinterface

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Helper function to describe security groups
func DescribeSecurityGroups(svc *ec2.Client, sgIds []string) *ec2.DescribeSecurityGroupsOutput {
	sgInput := &ec2.DescribeSecurityGroupsInput{
		GroupIds: sgIds,
	}

	sgResult, err := svc.DescribeSecurityGroups(context.TODO(), sgInput)
	if err != nil {
		log.Printf("unable to describe security groups, %v", err)
		return nil
	}

	return sgResult
}

func GetOpenNetworkInterfaces(securityGroupOutput *ec2.DescribeSecurityGroupsOutput) (bool, []VulnNISG) {
	vulnSgs := []VulnNISG{}
	isNIVuln := false

	for _, sg := range securityGroupOutput.SecurityGroups {
		vulnSg := []VulnSGConfig{}
		isVulnSg := false

		// iterate over each security group
		for _, ipPerms := range sg.IpPermissions {
			// scan for ipv4 vuln config
			for _, ipRange := range ipPerms.IpRanges {
				var port int32
				port = 0
				if ipPerms.FromPort != nil {
					port = *ipPerms.FromPort
				}

				if *ipRange.CidrIp == "0.0.0.0/0" {
					isVulnSg = true
					isNIVuln = true
					vulnSg = append(vulnSg, VulnSGConfig{
						Port:     port,
						Cidr:     *ipRange.CidrIp,
						Protocol: *ipPerms.IpProtocol,
						IsV6:     false,
					})
				}
			}

			// ipv6 vuln config
			for _, ipRange := range ipPerms.Ipv6Ranges {
				if *ipRange.CidrIpv6 == "::/0" {
					isVulnSg = true
					isNIVuln = true
					vulnSg = append(vulnSg, VulnSGConfig{
						Port:     *ipPerms.FromPort,
						Cidr:     *ipRange.CidrIpv6,
						Protocol: *ipPerms.IpProtocol,
						IsV6:     true,
					})
				}
			}
		}

		if isVulnSg {
			vulnSgs = append(vulnSgs, VulnNISG{
				VulnConfigs: vulnSg,
				GroupId:     *sg.GroupId,
				GroupName:   *sg.GroupName,
				OwnerId:     *sg.OwnerId,
				VpcId:       *sg.VpcId,
			})
		}
	}

	return isNIVuln, vulnSgs
}

func GetOpenNetworkInterfacesForRegion(region string) []VulnNI {
	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// Create an EC2 service client
	svc := ec2.NewFromConfig(cfg)

	// Describe network interfaces
	input := &ec2.DescribeNetworkInterfacesInput{}
	result, err := svc.DescribeNetworkInterfaces(context.TODO(), input)
	if err != nil {
		log.Fatalf("unable to describe network interfaces, %v", err)
	}

	// Filter and display the results
	vulnNIs := []VulnNI{}
	for _, ni := range result.NetworkInterfaces {
		if ni.Association != nil && ni.Association.PublicIp != nil {

			// Collect security group IDs
			var sgIds []string
			for _, sg := range ni.Groups {
				sgIds = append(sgIds, aws.ToString(sg.GroupId))
			}

			if len(sgIds) <= 0 {
				continue
			}

			// Describe the security groups
			sgOutputs := DescribeSecurityGroups(svc, sgIds)
			isVulnSg, vulnSGs := GetOpenNetworkInterfaces(sgOutputs)

			if isVulnSg {
				vulnNIs = append(vulnNIs, VulnNI{
					ResourceId:       aws.ToString(ni.NetworkInterfaceId),
					PublicIp:         aws.ToString(ni.Association.PublicIp),
					AvailabilityZone: aws.ToString(ni.AvailabilityZone),
					VulnNISGs:        vulnSGs,
				})
			}
		}
	}

	return vulnNIs
}

func IpInBypassList(ip string, bypassIps []string) bool {
	for _, bypassIP := range bypassIps {
		if ip == bypassIP {
			return true
		}
	}
	return false
}

func FilterOpenNetworkInterfaces(vulnNIs []VulnNI, allowListIps []string) []VulnNI {
	vulnNIsFiltered := []VulnNI{}

	for _, vulnNi := range vulnNIs {
		if !IpInBypassList(vulnNi.PublicIp, allowListIps) {
			vulnNIsFiltered = append(vulnNIsFiltered, vulnNi)
		}
	}

	return vulnNIsFiltered
}
