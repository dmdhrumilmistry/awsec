package networkinterface

import (
	"context"
	"log"

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

	// for _, sg := range sgResult.SecurityGroups {
	// 	fmt.Printf("  SecurityGroup: %s (%s)\n", aws.ToString(sg.GroupName), aws.ToString(sg.GroupId))
	// 	fmt.Printf("    Description: %s\n", aws.ToString(sg.Description))
	// 	fmt.Printf("    VPCId: %s\n", aws.ToString(sg.VpcId))

	// 	for _, perm := range sg.IpPermissions {
	// 		fmt.Printf("    Inbound Rule: %v\n", perm)
	// 		perm.
	// 	}
	// 	for _, perm := range sg.IpPermissionsEgress {
	// 		fmt.Printf("    Outbound Rule: %v\n", perm)
	// 	}
	// }
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
