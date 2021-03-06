package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"strings"
)

type LogChannel struct {
	StartTime     time.Time
	UserName      string
	ActualChannel ssh.Channel
	fd            *os.File
	fd_ttyrec     *os.File
	fd_req        *os.File
	initialBuffer *bytes.Buffer
	ttyrecBuffer  *bytes.Buffer
	reqBuffer     *bytes.Buffer
	unlogged      bool
	logMutex      *sync.Mutex
}

func writeTTYRecHeader(fd io.Writer, length int) {
	t := time.Now()

	tv := syscall.NsecToTimeval(t.UnixNano())

	binary.Write(fd, binary.LittleEndian, int32(tv.Sec))
	binary.Write(fd, binary.LittleEndian, int32(tv.Usec))
	binary.Write(fd, binary.LittleEndian, int32(length))
}

func NewLogChannel(startTime time.Time, channel ssh.Channel, username string) *LogChannel {
	return &LogChannel{
		StartTime:     startTime,
		UserName:      username,
		ActualChannel: channel,
		initialBuffer: bytes.NewBuffer([]byte{}),
		ttyrecBuffer:  bytes.NewBuffer([]byte{}),
		reqBuffer:     bytes.NewBuffer([]byte{}),
		logMutex:      &sync.Mutex{},
	}
}

func (l *LogChannel) SyncToFile(remote_name string) error {
	var err error

	filepath := fmt.Sprintf("%s/%s/%s", config.Global.LogPath, remote_name, l.UserName)
	err = os.MkdirAll(filepath, 0750)
	if err != nil {
		return fmt.Errorf("Unable to create required log directory (%s): %s", filepath, err)
	}
	filename := filepath + "/" + fmt.Sprintf("ssh_log_%s", l.StartTime.Format(time.RFC3339))

	l.logMutex.Lock()

	l.fd, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0640)
	if err != nil {
		return err
	}

	_, err = l.initialBuffer.WriteTo(l.fd)
	if err != nil {
		return err
	}
	l.initialBuffer.Reset()
	l.initialBuffer = nil

	l.fd_ttyrec, err = os.OpenFile(filename+".ttyrec", os.O_WRONLY|os.O_CREATE, 0640)
	if err != nil {
		return err
	}

	_, err = l.ttyrecBuffer.WriteTo(l.fd_ttyrec)
	if err != nil {
		return err
	}
	l.ttyrecBuffer.Reset()
	l.ttyrecBuffer = nil

	l.fd_req, err = os.OpenFile(filename+".req", os.O_WRONLY|os.O_CREATE, 0640)
	if err != nil {
		return err
	}

	_, err = l.reqBuffer.WriteTo(l.fd_req)
	if err != nil {
		return err
	}
	l.reqBuffer.Reset()
	l.reqBuffer = nil

	l.logMutex.Unlock()

	return nil
}

func (l *LogChannel) Read(data []byte) (int, error) {
	return l.ActualChannel.Read(data)
}

func (l *LogChannel) Write(data []byte) (int, error) {
	l.logMutex.Lock()
	if !l.unlogged && len(data) > 0 {
		if l.fd != nil {
			l.fd.Write(data)
		} else {
			l.initialBuffer.Write(data)
		}
		if l.fd_ttyrec != nil {
			writeTTYRecHeader(l.fd_ttyrec, len(data))
			l.fd_ttyrec.Write(data)
		} else {
			writeTTYRecHeader(l.ttyrecBuffer, len(data))
			l.ttyrecBuffer.Write(data)
		}
	}
	l.logMutex.Unlock()

	return l.ActualChannel.Write(data)
}

func (l *LogChannel) CloseWrite() error {
	return l.ActualChannel.CloseWrite()
}

func (l *LogChannel) Stderr() io.ReadWriter {
	return l.ActualChannel.Stderr()
}

func (l *LogChannel) Close() error {
	if l.fd != nil {
		l.fd.Close()
	}
	if l.fd_ttyrec != nil {
		l.fd_ttyrec.Close()
	}
	if l.fd_req != nil {
		l.fd_req.Close()
	}

	return l.ActualChannel.Close()
}

func (l *LogChannel) LogRequest(r *ssh.Request) {
	var payload interface{}
	if r.Type == "env" {
		type envRequest struct {
			Name  string
			Value string
		}
		var pl envRequest
		if err := ssh.Unmarshal(r.Payload, &pl); err != nil {
			payload = r.Payload
		} else {
			payload = fmt.Sprintf("name: %s, value: %s", pl.Name, pl.Value)
		}
	} else if r.Type == "exec" {
		type execRequest struct {
			Command string
		}
		var pl execRequest
		if err := ssh.Unmarshal(r.Payload, &pl); err != nil {
			payload = r.Payload
		} else {
			payload = pl.Command

			toks := strings.Split(pl.Command, " ")
			if toks[0] == "scp" || toks[0] == "rsync" {
				l.unlogged = true
			}
		}
	} else {
		payload = r.Payload
	}
	logLine := fmt.Sprintf("%s: Request Type - %s - Want Reply: %t - Payload: %#v\r\n", time.Now().Format(time.RFC3339), r.Type, r.WantReply, payload)
	if l.fd_req != nil {
		l.fd_req.Write([]byte(logLine))
	} else {
		l.reqBuffer.Write([]byte(logLine))
	}
}

func (l *LogChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return l.ActualChannel.SendRequest(name, wantReply, payload)
}
