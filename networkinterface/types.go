package networkinterface

type VulnNISG struct {
	VulnConfigs []VulnSGConfig
	GroupId     string
	GroupName   string
	OwnerId     string
	VpcId       string
}

type VulnSGConfig struct {
	Port     int32
	Cidr     string
	Protocol string
	IsV6     bool
}

type VulnNI struct {
	ResourceId       string
	PublicIp         string
	AvailabilityZone string
	VulnNISGs        []VulnNISG
}
