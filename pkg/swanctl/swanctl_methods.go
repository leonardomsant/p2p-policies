package swanctl

import (
	"errors"
	"fmt"
	"os"
	"strings"

	api "github.com/leonardomsant/p2p-policies/api/v1"
	"github.com/leonardomsant/p2p-policies/pkg/vici"
)

func (c *ConfigurationFile) LoadConnections() error {
	var err error

	for _, conn := range c.Connections {
		_, err = vici.LoadConnections(conn)
	}

	return err
}

func (c *ConfigurationFile) getNodeConf(nodesConf []string,
	policiesConf []string, protocolsConf []string) {
	for _, node := range nodesConf {
		nodeInfo := strings.Split(node, "#")
		if CurrentNode == nodeInfo[0] {
			c.Hostname = nodeInfo[0]
			c.LocalAddr = nodeInfo[1]
			c.LocalNet = nodeInfo[2]
			continue
		}

		nodeConnection := vici.SystemNodeConnection{
			Name:        "k8s-node-" + nodeInfo[0],
			ReauthTime:  14400,
			RekeyTime:   3600,
			Unique:      "never",
			LocalAddrs:  []string{c.LocalAddr},
			RemoteAddrs: []string{nodeInfo[1]},
			Local: &vici.LocalOpts{
				Auth:  "pubkey",
				Certs: CertificatePrefix + c.Hostname + CertificateExtension,
			},
			Remote: &vici.RemoteOpts{
				ID:      "CN=*",
				Auth:    "pubkey",
				CACerts: SystemLocalCACert0 + "," + SystemLocalCACert1,
			},
		}

		nodeConnection.Children = make(map[string]*vici.ChildSA)
		for _, policy := range policiesConf {
			replacer := strings.NewReplacer("/", "_", "-", "_")
			childName := replacer.Replace(policy)

			policyEgress := childName + "_egress"
			remoteTS := nodeInfo[2] + "[" + policy + "]"
			childEgress := &vici.ChildSA{
				Mode:                   "tunnel",
				StartAction:            "start",
				LocalTrafficSelectors:  []string{c.LocalNet},
				RemoteTrafficSelectors: []string{remoteTS},
				Updown:                 "/usr/lib/ipsec/_updown iptables",
			}
			nodeConnection.Children[policyEgress] = childEgress

			policyIngress := childName + "_ingress"
			localTS := c.LocalNet + "[" + policy + "]"
			remoteTS = nodeInfo[2]
			childIngress := &vici.ChildSA{
				Mode:                   "tunnel",
				StartAction:            "start",
				LocalTrafficSelectors:  []string{localTS},
				RemoteTrafficSelectors: []string{remoteTS},
				Updown:                 "/usr/lib/ipsec/_updown iptables",
			}
			nodeConnection.Children[policyIngress] = childIngress
		}

		for _, protocol := range protocolsConf {
			localTS := c.LocalNet + "[" + protocol + "]"
			remoteTS := nodeInfo[2] + "[" + protocol + "]"
			childProtocol := &vici.ChildSA{
				Mode:                   "tunnel",
				StartAction:            "start",
				LocalTrafficSelectors:  []string{localTS},
				RemoteTrafficSelectors: []string{remoteTS},
				Updown:                 "/usr/lib/ipsec/_updown iptables",
			}
			nodeConnection.Children[protocol] = childProtocol
		}

		c.Connections = append(c.Connections, nodeConnection)
	}
}

func (c *ConfigurationFile) getLocalConf() {
	conn := vici.Connection{
		Name: "k8s-node-local",
		Children: map[string]*vici.ChildSA{
			"k8s-node-bypass": &(vici.ChildSA{
				Mode:                   "pass",
				StartAction:            "trap",
				LocalTrafficSelectors:  []string{c.LocalNet},
				RemoteTrafficSelectors: []string{c.LocalNet},
			}),
		},
	}

	c.Connections = append(c.Connections, conn)
}

func (c *ConfigurationFile) writeChildrenSA(childSAs map[string]*vici.ChildSA) {
	fmt.Fprintln(c.File, "\t\tchildren {")

	for name, sa := range childSAs {
		fmt.Fprint(c.File, "\t\t\t", name, " {\n")
		fmt.Fprintln(c.File, "\t\t\t\tstart_action = ", sa.StartAction)
		fmt.Fprintln(c.File, "\t\t\t\tlocal_ts =", sa.LocalTrafficSelectors)
		fmt.Fprintln(c.File, "\t\t\t\tremote_ts =", sa.RemoteTrafficSelectors)
		fmt.Fprintln(c.File, "\t\t\t\tmode = ", sa.Mode)
		fmt.Fprintln(c.File, "\t\t\t}")
	}

	fmt.Fprintln(c.File, "\t\t}")
}

func (c *ConfigurationFile) writeConf() error {
	var err error
	c.File, err = os.Create(IPsecConfFile)
	if err != nil {
		fmt.Println(err)
		c.File.Close()
		return err
	}

	fmt.Fprintln(c.File, "connections {")

	for _, node := range c.Connections {
		switch n := node.(type) {
		case vici.SystemNodeConnection:
			fmt.Fprint(c.File, "\t"+n.Name+" {\n")
			fmt.Fprintln(c.File, "\t\treauth_time = ", n.ReauthTime)
			fmt.Fprintln(c.File, "\t\trekey_time = ", n.RekeyTime)
			fmt.Fprintln(c.File, "\t\tunique = ", n.Unique)
			fmt.Fprintln(c.File, "\t\tlocal_addrs =", n.LocalAddrs)
			fmt.Fprintln(c.File, "\t\tremote_addrs = ", n.RemoteAddrs)

			fmt.Fprintln(c.File, "\t\tlocal {")
			fmt.Fprintln(c.File, "\t\t\tauth = ", n.Local.Auth)
			fmt.Fprintln(c.File, "\t\t\tcerts =", n.Local.Certs)
			fmt.Fprintln(c.File, "\t\t}")

			fmt.Fprintln(c.File, "\t\tremote {")
			fmt.Fprintln(c.File, "\t\t\tid = ", n.Remote.ID)
			fmt.Fprintln(c.File, "\t\t\tauth = ", n.Remote.Auth)
			fmt.Fprintln(c.File, "\t\t\tcacerts = ", n.Remote.CACerts)
			fmt.Fprintln(c.File, "\t\t}")

			c.writeChildrenSA(n.Children)

			fmt.Fprintln(c.File, "\t}")
		case vici.Connection:
			fmt.Fprintln(c.File, "\t"+n.Name+" {")
			c.writeChildrenSA(n.Children)
			fmt.Fprintln(c.File, "\t}")
		default:
			err = errors.New("type not supported")
		}
	}
	fmt.Fprintln(c.File, "}")

	return err
}

func (c *ConfigurationFile) Generate(resource api.P2PSecurityPolicy) error {
	c.getNodeConf(resource.Spec.Nodes, resource.Spec.Policies,
		resource.Spec.Protocols)
	c.getLocalConf()
	return c.writeConf()
}

// TODO: Use write() to generate/iterate the file with updated
//       values for policy
// TODO: Write a function able to generate and increment k8s-node.conf with
//      SystemNodeConnection data.
/*
import (
	"reflect"
)

func writeSystemNodeConnection(file *os.File, s vici.SystemNodeConnection) {
	delimiterOpen  := " {"
	delimiterClose := "}"
	equal := " = "

	tab := "\t"
	fmt.Fprintln(file, tab, s.Name, delimiterOpen)

	v := reflect.ValueOf(s)
	t := reflect.TypeOf(s)
	for i := 0; i < v.NumField(); i++ {
		depth := 2
		spacing := strings.Repeat(tab, depth)

		field := t.Field(i)
		value := v.Field(i)
		fieldType := value.Type()

		switch fieldType.Kind() {
		case reflect.String, reflect.Int, reflect.Slice: // Most of the fields
			fmt.Fprintln(file, spacing, field.Name, equal, value.Interface())
		case reflect.Pointer: // Local or Remote
			fmt.Fprintln(file, spacing, field.Name, delimiterOpen)
			depth = 3
			spacing = strings.Repeat(tab, depth)
			ptr := value.Elem()
			for _, key := range ptr.MapKeys() {
				data := ptr.MapIndex(key).Interface()
				fmt.Fprintln(file, spacing, key.Interface(), equal, data)
			}
			fmt.Fprintln(file, spacing, delimiterClose)
		case reflect.Map: // Children
			fmt.Fprintln(file, spacing, field.Name, delimiterOpen)
			// TODO: Map keys and write Children data
			// depth = 3
			// spacing = strings.Repeat(tab, depth)
			// childMap := value.Elem()
			// for _, key := range childMap.MapKeys() {
			//
			//}
		default:
			fmt.Fprintln(file, spacing, delimiterClose)
		}
	}
	fmt.Fprintln(file, tab, delimiterClose)
}
*/

/* TODO: Write a function able to generate and increment k8s-node.conf
         with Connection data.
func writeConnection(file *os.File, c vici.Connection) {}
*/

/* TODO: Write a function able to fully generate k8-node.conf file
func (c *ConfigurationFile) write() error {
	c.File, err := os.Create(IPsecConfFile)
	if err != nil {
		fmt.Println(err)
		c.File.Close()
		return err
	}

	delimiterOpen := " {"
	delimiterClose := "}"
	fmt.Fprintln(c.File, "connections" + delimiterOpen)

	for _, node := range c.Conns {
		switch n := node.(type) {
		case vici.SystemNodeConnection:
			writeSystemNodeConnection(c.File, n)
		case vici.Connection:
			writeConnection(c.File, n)
		default:
			err = errors.New("type not supported")
		}
	}

	fmt.Fprintln(c.File, delimiterClose)
	c.File.Close()
    return err
}
*/
