package vici

import (
	"errors"
	"fmt"

	govici "github.com/strongswan/govici/vici"
)

func CommandRequest(command string, msg *govici.Message) (*govici.Message, error) {
	session, err := govici.NewSession()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer session.Close()

	ret, err := session.CommandRequest(command, msg)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return ret, err
}

func LoadConnections(connections ...any) ([]*govici.Message, error) {
	results := []*govici.Message{}
	session, err := govici.NewSession()
	if err != nil {
		fmt.Println(err)
		return results, err
	}
	defer session.Close()

	for _, connection := range connections {
		m := govici.NewMessage()
		switch conn := connection.(type) {
		case Connection:
			c, err := govici.MarshalMessage(&conn)
			if err != nil {
				fmt.Println("Unable to Marshal message")
				break
			}

			if err := m.Set(conn.Name, c); err != nil {
				fmt.Println("Unable to create message of type Connection")
				break
			}
		case SystemNodeConnection:
			c, err := govici.MarshalMessage(&conn)
			if err != nil {
				fmt.Println("Unable to Marshal message")
				break
			}

			if err = m.Set(conn.Name, c); err != nil {
				fmt.Println("Unable to create message of type SystemNodeConnection")
				break
			}
		default:
			err = errors.New("type not supported")
		}

		if err != nil {
			break
		}
		request, _ := session.CommandRequest("load-conn", m)
		results = append(results, request)
	}

	return results, err
}
