package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type SSHConfig struct {
	Global  SSHConfigGlobal            `yaml:"global"`
	Servers map[string]SSHConfigServer `yaml:"servers"`
	Keys    map[string][]string        `yaml:"keys"`
}

type SSHConfigGlobal struct {
	LogPath        string   `yaml:"log_path"`
	HostKeyPaths   []string `yaml:"host_keys"`
	ListenPath     string   `yaml:"listen_path"`
	KnownHostsFile string   `yaml:"known_hosts_file"`
	KeytabPath     string   `yaml:"keytab_file"`
}

type SSHConfigServer struct {
	HostPubKeyFiles []string `yaml:"host_pubkeys"`
	ConnectPath     string   `yaml:"connect_path"`
}

func fetchConfig(filename string) (*SSHConfig, error) {
	configData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to open config file: %s", err)
	}

	config := &SSHConfig{}

	err = yaml.Unmarshal(configData, config)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse YAML config file: %s", err)
	}

	return config, nil
}
