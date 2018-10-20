package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"time"
)

type SSHServer struct {
	sshConfig *ssh.ServerConfig
}

func NewSSHServer() (*SSHServer, error) {
	s := &SSHServer{
		sshConfig: &ssh.ServerConfig{
			NoClientAuth:  true,
			ServerVersion: "SSH-2.0-BASTION",
		},
	}

	for _, keyPath := range config.Global.HostKeyPaths {
		hostKey, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("Unable to read host key file (%s): %s", keyPath, err)
		}

		signer, err := ssh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("Invalid SSH Host Key (%s)", keyPath)
		}

		s.sshConfig.AddHostKey(signer)
	}

	return s, nil
}

func (s *SSHServer) HandleConn(c net.Conn, username, serverName string, groupSIDs []string) {
	//log.Printf("Starting Accept SSH Connection...")
	startTime := time.Now()

	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		//log.Printf("Exiting as there is a config problem...")
		c.Close()
		return
	}
	defer WriteAuthLog("Connection closed by %s (User: %s).", sshConn.RemoteAddr(), username)

	go ssh.DiscardRequests(reqs)
	newChannel := <-chans
	if newChannel == nil {
		//log.Printf("Exiting as couldn't fetch the channel...")
		sshConn.Close()
		return
	}

	switch newChannel.ChannelType() {
	case "session":
		s.SessionForward(startTime, sshConn, newChannel, chans, username, serverName, groupSIDs)
	default:
		newChannel.Reject(ssh.UnknownChannelType, "connection flow not supported, only interactive sessions are permitted.")
	}

	//log.Printf("ALL OK, closing as nothing left to do...")
	sshConn.Close()
}
