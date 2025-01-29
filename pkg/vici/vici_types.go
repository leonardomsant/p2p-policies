package vici

type LocalOpts struct {
	Auth  string `vici:"auth"`
	Certs string `vici:"certs"`
}

type RemoteOpts struct {
	ID      string `vici:"id"`
	Auth    string `vici:"auth"`
	CACerts string `vici:"cacerts"`
}

type ChildSA struct {
	Mode                   string   `vici:"mode"`
	StartAction            string   `vici:"start_action"`
	LocalTrafficSelectors  []string `vici:"local_ts"`
	RemoteTrafficSelectors []string `vici:"remote_ts"`
	Updown                 string   `vici:"updown"`
	Inactivity             int      `vici:"inactivity"`
}

type Connection struct {
	Name     string
	Children map[string]*ChildSA `vici:"children"`
}

type SystemNodeConnection struct {
	ReauthTime  int         `vici:"reauth_time"`
	RekeyTime   int         `vici:"rekey_time"`
	Unique      string      `vici:"unique"`
	Mobike      string      `vici:"mobike"`
	DPDDelay    int         `vici:"dpd_delay"`
	DPDTimeout  int         `vici:"dpd_timeout"`
	LocalAddrs  []string    `vici:"local_addrs"`
	RemoteAddrs []string    `vici:"remote_addrs"`
	Local       *LocalOpts  `vici:"local"`
	Remote      *RemoteOpts `vici:"remote"`

	// Note: govici does not support golang interfaces
	Name     string
	Children map[string]*ChildSA `vici:"children"`
}
