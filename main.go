package main

import (
	"fmt"
)

func IpInBypassList(ip string, bypassIps []string) bool {
	for _, bypassIP := range bypassIps {
		if ip == bypassIP {
			return true
		}
	}
	return false
}

func FilterOpenNetworkInterfaces(vulnNIs []string, allowListIps []string) []string {
	vulnNIsFiltered := []string{}

	for _, vulnNi := range vulnNIs {
		if !IpInBypassList(vulnNi, allowListIps) {
			vulnNIsFiltered = append(vulnNIsFiltered, vulnNi)
		}
	}

	return vulnNIsFiltered
}

func main() {
	a := []string{"a", "v", "c"}
	b := []string{"a", "v"}

	fmt.Println(FilterOpenNetworkInterfaces(a, b))
}
