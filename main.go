package main

import (
	"gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v6/service"
	"net/http"
	"os"
	//"fmt"
	"github.com/jessevdk/go-flags"
	"log"

	"gopkg.in/jcmturner/gokrb5.v6/credentials"
	"gopkg.in/jcmturner/gokrb5.v6/keytab"
)

var config *SSHConfig

var opts struct {
	Config string `short:"c" long:"config" description:"Configuration YAML file location" required:"true" default:"/etc/ssh-bastion/ssh-bastion.yml"`
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	if _, err := os.Stat(opts.Config); err != nil {
		log.Fatalf("Specified config file doesn't exist!\n")
	}

	config, err = fetchConfig(opts.Config)
	if err != nil {
		panic(err)
	}

	s, err := NewSSHServer()
	if err != nil {
		panic(err)
	}

	kt, err := keytab.Load(config.Global.KeytabPath)
	if err != nil {
		panic(err)
	}

	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
	c := service.NewConfig(kt)

	handler := SSHProxy{Server: s}

	kerberosHandler := service.SPNEGOKRB5Authenticate(handler, c, l)

	log.Fatal(http.ListenAndServe(config.Global.ListenPath, kerberosHandler))
}

type SSHProxy struct {
	Server *SSHServer
}

func (s SSHProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != "CONNECT" {
		response.WriteHeader(400)
		return
	}

	ctx := request.Context()
	validUser, ok := ctx.Value(service.CTXKeyAuthenticated).(bool)
	if !ok || !validUser {
		return
	}

	creds, ok := ctx.Value(service.CTXKeyCredentials).(goidentity.Identity)
	if !ok {
		return
	}

	adCreds, ok := creds.Attributes()[credentials.AttributeKeyADCredentials].(credentials.ADCredentials)
	if !ok {
		return
	}

	response.WriteHeader(200)
	response.(http.Flusher).Flush()

	hj, _ := response.(http.Hijacker)
	conn, _, _ := hj.Hijack()

	s.Server.HandleConn(conn, creds.UserName(), request.URL.Host, adCreds.GroupMembershipSIDs)
}

func WriteAuthLog(format string, v ...interface{}) {
	log.Printf(format, v...)
}
