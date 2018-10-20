package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func (s *SSHServer) SessionForward(startTime time.Time, sshConn *ssh.ServerConn, newChannel ssh.NewChannel, chans <-chan ssh.NewChannel, userName, targetAddress string, groupSIDs []string) {
	rawsesschan, sessReqs, err := newChannel.Accept()
	if err != nil {
		log.Printf("Unable to Accept Session, closing connection...")
		sshConn.Close()
		return
	}
	defer sshConn.Close()

	sesschan := NewLogChannel(startTime, rawsesschan, userName)

	readyChan := make(chan bool, 1)

	// Proxy the channel and its requests
	maskedReqs := make(chan *ssh.Request, 5)
	go func() {
		// For the pty-req and shell request types, we have to reply to those right away.
		// This is for PuTTy compatibility - if we don't, it won't allow any input.
		// We also have to change them to WantReply = false,
		// or a double reply will cause a fatal error client side.
		for req := range sessReqs {
			if req.Type == "auth-agent-req@openssh.com" {
				if req.WantReply {
					req.Reply(true, []byte{})
				}
				continue
			} else if req.Type == "pty-req" && req.WantReply {
				req.Reply(true, []byte{})
				req.WantReply = false
			} else if req.Type == "shell" && req.WantReply {
				req.Reply(true, []byte{})
				req.WantReply = false

				readyChan <- true
			} else if req.Type == "exec" {
				readyChan <- true
			}

			maskedReqs <- req
		}
	}()

	<-readyChan

	logFilename := strings.Split(targetAddress, ":")[0]
	sanitizedLogFilename := strings.Replace(logFilename, "/", "_", -1)
	err = sesschan.SyncToFile(sanitizedLogFilename)
	if err != nil {
		fmt.Fprintf(sesschan, "Failed to Initialize Session.\r\n")
		sesschan.Close()
		return
	}

	var privateKeys []ssh.Signer

	for _, sid := range groupSIDs {
		keys, ok := config.Keys[sid]
		if !ok {
			continue
		}

		for _, keyPath := range keys {
			userKey, err := ioutil.ReadFile(keyPath)
			if err != nil {
				log.Printf("Could not load private key file %s: %v", keyPath, err)
				continue
			}

			signer, err := ssh.ParsePrivateKey(userKey)
			if err != nil {
				log.Printf("Could not parse private key file %s: %v", keyPath, err)
				continue
			}

			privateKeys = append(privateKeys, signer)
		}
	}

	WriteAuthLog("Connecting to remote for relay (%s) by %s from %s.", targetAddress, userName, sshConn.RemoteAddr())
	var clientConfig *ssh.ClientConfig
	clientConfig = &ssh.ClientConfig{
		User: sshConn.User(),
		Auth: []ssh.AuthMethod{ssh.PublicKeys(privateKeys...)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			checker, err := knownhosts.New(config.Global.KnownHostsFile)
			if err != nil {
				return err
			}
			err = checker(hostname, remote, key)
			if err == nil {
				return nil
			}

			keyError := err.(*knownhosts.KeyError)
			if len(keyError.Want) != 0 {
				return err
			}

			f, err := os.OpenFile(config.Global.KnownHostsFile, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}

			defer f.Close()

			line := knownhosts.Line([]string{hostname}, key) + "\n"

			if _, err = f.WriteString(line); err != nil {
				return err
			}

			return nil
		},
	}

	log.Printf("Getting ready to dial remote SSH %s", targetAddress)
	client, err := ssh.Dial("tcp", targetAddress, clientConfig)
	if err != nil {
		fmt.Fprintf(sesschan, "Connect failed: %v\r\n", err)
		sesschan.Close()
		return
	}
	defer client.Close()
	log.Printf("Dialled remote SSH Successfully...")

	// Handle all incoming channel requests
	go func() {
		for newChannel = range chans {
			if newChannel == nil {
				return
			}

			if newChannel.ChannelType() != "direct-tcpip" {
				newChannel.Reject(ssh.Prohibited, "remote server denied channel request")
				continue
			}

			log.Printf("Setting up TCP/IP channel to remote %s", targetAddress)
			channel2, reqs2, err := client.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
			if err != nil {
				newChannel.Reject(ssh.ConnectionFailed, "channel request failed")
				continue
			}

			channel, reqs, err := newChannel.Accept()
			if err != nil {
				continue
			}

			go proxy(reqs, reqs2, channel, channel2, sesschan)
		}
	}()

	// Forward the session channel
	log.Printf("Setting up channel to remote %s", targetAddress)
	channel2, reqs2, err := client.OpenChannel("session", []byte{})
	if err != nil {
		fmt.Fprintf(sesschan, "Remote session setup failed: %v\r\n", err)
		sesschan.Close()
		return
	}
	WriteAuthLog("Connected to remote for relay (%s) by %s from %s.", targetAddress, userName, sshConn.RemoteAddr())
	defer WriteAuthLog("Disconnected from remote for relay (%s) by %s from %s.", targetAddress, userName, sshConn.RemoteAddr())

	log.Printf("Starting session proxy...")
	proxy(maskedReqs, reqs2, sesschan, channel2, sesschan)
}

func proxy(reqs1, reqs2 <-chan *ssh.Request, channel1 ssh.Channel, channel2 ssh.Channel, log *LogChannel) {
	var closer sync.Once
	closeFunc := func() {
		channel1.Close()
		channel2.Close()
	}

	defer closer.Do(closeFunc)

	closerChan := make(chan bool, 1)

	// From remote, to client.
	go func() {
		io.Copy(channel1, channel2)
		closerChan <- true
	}()

	go func() {
		io.Copy(channel2, channel1)
		closerChan <- true
	}()

	for {
		select {
		case req := <-reqs1:
			if req == nil {
				return
			}
			log.LogRequest(req)
			b, err := channel2.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)
		case req := <-reqs2:
			if req == nil {
				return
			}
			log.LogRequest(req)
			b, err := channel1.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)
		case <-closerChan:
			return
		}
	}
}
