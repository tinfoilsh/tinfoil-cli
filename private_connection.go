package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/websocket"
)

func (c *cpClient) connect(ctx context.Context, id string, port int) (net.Conn, error) {
	if err := validateControlplaneURL(c.baseURL); err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(c.baseURL + pathf("/api/containers/%s/connect/%s", id, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if endpoint.Scheme == "https" {
		endpoint.Scheme = "wss"
	} else {
		endpoint.Scheme = "ws"
	}
	config, err := websocket.NewConfig(endpoint.String(), c.baseURL)
	if err != nil {
		return nil, err
	}
	config.Header.Set("Authorization", "Bearer "+c.apiKey)
	config.TlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := config.DialContext(deadline)
	if err != nil {
		return nil, fmt.Errorf("private connection: %w", err)
	}
	conn.PayloadType = websocket.BinaryFrame
	return conn, nil
}

func privateDialer(client *cpClient, id string, port int) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) { return client.connect(ctx, id, port) }
}

func containerNamed(client *cpClient, name string) (containerView, error) {
	var rows []containerView
	if _, err := client.do("GET", "/api/containers", nil, nil, &rows); err != nil {
		return containerView{}, err
	}
	for _, row := range rows {
		if row.Name == name && !row.Debug {
			_, err := client.do("GET", pathf("/api/containers/%s", row.ID), nil, nil, &row)
			return row, err
		}
	}
	return containerView{}, &cpError{Status: http.StatusNotFound, Message: "container not found"}
}
