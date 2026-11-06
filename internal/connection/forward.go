package connection

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const maxPort = 65535

type ForwardSpec struct {
	Bind   string
	Local  int
	Remote int
}

func ParseForwardSpec(raw string) (ForwardSpec, error) {
	spec := ForwardSpec{Bind: "127.0.0.1"}
	fields := strings.Split(raw, ":")
	if len(fields) == 3 {
		spec.Bind, fields = fields[0], fields[1:]
		if spec.Bind == "" {
			return spec, fmt.Errorf("invalid forward %q: empty bind address; drop it to listen on 127.0.0.1, or name 0.0.0.0 to listen on every interface", raw)
		}
	}
	if len(fields) != 2 {
		return spec, fmt.Errorf("invalid forward %q: want [bind:]<local-port>:<enclave-port>", raw)
	}
	for i, into := range []*int{&spec.Local, &spec.Remote} {
		port, err := strconv.Atoi(fields[i])
		if err != nil || port < 1 || port > maxPort {
			return spec, fmt.Errorf("invalid forward %q: port %q must be 1..65535", raw, fields[i])
		}
		*into = port
	}
	return spec, nil
}

func ListenAndForward(tun *Tunnel, specs []ForwardSpec, listening func(net.Addr, int)) error {
	failed := make(chan error, len(specs))
	for _, spec := range specs {
		listener, err := net.Listen("tcp", net.JoinHostPort(spec.Bind, strconv.Itoa(spec.Local)))
		if err != nil {
			return err
		}
		defer listener.Close()
		if listening != nil {
			listening(listener.Addr(), spec.Remote)
		}

		go func() {
			for {
				local, err := listener.Accept()
				if err != nil {
					failed <- err
					return
				}
				go func() {
					stream, err := tun.Dial(spec.Remote)
					if err != nil {
						log.WithError(err).Error("opening tunnel")
						local.Close()
						return
					}
					Splice(local, stream)
				}()
			}
		}()
	}
	return <-failed
}
