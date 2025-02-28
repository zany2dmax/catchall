package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Wyse MAC Address Prefixes (OUI)
var wyseMacPrefixes = []string{
	"00:1C:23", "00:80:64", "D4:4A:2E", "34:17:EB",
}

// Wyse SNMP Identifiers
var wyseSNMPIdentifiers = []string{"Wyse", "Dell", "ThinOS"}

// Known Wyse Ports
var wysePorts = []int{22, 3389, 443, 8080, 8443, 161, 69}

// Function to format port list as a string for Nmap
func formatPorts() string {
	portStrings := []string{}
	for _, port := range wysePorts {
		portStrings = append(portStrings, fmt.Sprintf("%d", port))
	}
	return strings.Join(portStrings, ",")
}

// Function to check for Wyse MAC address prefixes
func isWyseMAC(mac string) bool {
	for _, prefix := range wyseMacPrefixes {
		if strings.HasPrefix(strings.ToUpper(mac), prefix) {
			return true
		}
	}
	return false
}

// Function to scan ARP for Wyse MAC addresses
func scanARP() {
	fmt.Println("Scanning for Wyse Thin Clients via ARP...")
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.HardwareAddr == nil {
			continue
		}

		handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			continue
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			ethLayer := packet.LinkLayer()
			if ethLayer != nil {
				mac := ethLayer.LayerContents()
				macAddr := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
				if isWyseMAC(macAddr) {
					fmt.Printf("Wyse Thin Client detected via ARP: MAC %s on %s\n", macAddr, iface.Name)
				}
			}
		}
	}
}

// Function to query SNMP for Wyse devices
func scanSNMP(target string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("Querying SNMP on %s...\n", target)

	snmp := &gosnmp.GoSNMP{
		Target:    target,
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}
	err := snmp.Connect()
	if err != nil {
		return
	}
	defer snmp.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"} // sysDescr
	result, err := snmp.Get(oids)
	if err != nil {
		return
	}

	for _, variable := range result.Variables {
		if variable.Type == gosnmp.OctetString {
			sysDesc := string(variable.Value.([]byte))
			for _, id := range wyseSNMPIdentifiers {
				if strings.Contains(sysDesc, id) {
					fmt.Printf("SNMP Wyse Detected: %s (%s)\n", target, sysDesc)
				}
			}
		}
	}
}

// Function to run Nmap for Wyse fingerprinting
func scanNmap(target string, wg *sync.WaitGroup) {
	defer wg.Done()
	ports := formatPorts()
	fmt.Printf("Running Nmap on %s (Ports: %s)...\n", target, ports)

	cmd := exec.Command("nmap", "-p", ports, "-O", "--script=http-title", target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Nmap execution failed:", err)
		return
	}

	matched, _ := regexp.MatchString(`(?i)Wyse|ThinOS|Dell`, string(output))
	if matched {
		fmt.Printf("Nmap identified Wyse Thin Client: %s\n", target)
	}
}

// Function to get the list of all IPs in a subnet
func getSubnetIPs(subnet string) []string {
	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Fatal(err)
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips
}

// Helper function to increment IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Function to detect the network subnet of the system
func getNetworkSubnet() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					return ipNet.String()
				}
			}
		}
	}
	log.Fatal("No valid network interface found")
	return ""
}

func main() {
	// Detect local subnet automatically
	subnet := getNetworkSubnet()
	fmt.Printf("Detected Subnet: %s\n", subnet)

	// Get all IPs in the subnet
	ipList := getSubnetIPs(subnet)

	// Start ARP scan
	scanARP()

	// Use goroutines for parallel scanning
	var wg sync.WaitGroup

	// Run SNMP scan on all IPs
	for _, ip := range ipList {
		wg.Add(1)
		go scanSNMP(ip, &wg)
	}

	// Run Nmap scan on all IPs
	for _, ip := range ipList {
		wg.Add(1)
		go scanNmap(ip, &wg)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	fmt.Println("Scanning complete.")
}
