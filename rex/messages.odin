package main

import "core:encoding/json"

Client_Info :: struct {
	kind:     string `json:"kind,omitempty"`,
	platform: string `json:"platform,omitempty"`,
	name:     string `json:"name,omitempty"`,
	version:  string `json:"version,omitempty"`,
	label:    string `json:"label,omitempty"`,
}

Hello :: struct {
	message_type:     string `json:"type"`,
	reconnect_token:  string `json:"reconnect_token,omitempty"`,
	client:           ^Client_Info `json:"client,omitempty"`,
	api_revision:     int `json:"api_revision,omitempty"`,
	api_min_revision: int `json:"api_min_revision,omitempty"`,
}

Welcome_Limits :: struct {
	max_message_bytes: int `json:"max_message_bytes"`,
}

Welcome_Client :: struct {
	id:              string `json:"id"`,
	reconnect_token: string `json:"reconnect_token"`,
	resumed:         bool `json:"resumed,omitempty"`,
}

Carrier :: struct {
	carrier: string `json:"carrier"`,
	port:    int `json:"port"`,
	alpn:    []string `json:"alpn,omitempty"`,
}

Welcome :: struct {
	message_type:        string `json:"type"`,
	protocol:            string `json:"protocol"`,
	limits:              Welcome_Limits `json:"limits"`,
	carriers:            []Carrier `json:"carriers,omitempty"`,
	client:              ^Welcome_Client `json:"client,omitempty"`,
	features:            []string `json:"features,omitempty"`,
	api_revision:        int `json:"api_revision,omitempty"`,
	api_server_revision: int `json:"api_server_revision,omitempty"`,
	api_min_revision:    int `json:"api_min_revision,omitempty"`,
}

Request :: struct {
	message_type: string `json:"type"`,
	id:           string `json:"id"`,
	method:       string `json:"method"`,
	payload:      ^json.Value `json:"payload,omitempty"`,
}

Error :: struct {
	code:    string `json:"code"`,
	message: string `json:"message"`,
	status:  int `json:"status"`,
}

Response :: struct {
	message_type: string `json:"type"`,
	id:           string `json:"id"`,
	seq:          int `json:"seq"`,
	payload:      ^json.Value `json:"payload,omitempty"`,
	error:        ^Error `json:"error,omitempty"`,
}

Event :: struct {
	message_type: string `json:"type"`,
	seq:          int `json:"seq"`,
	payload:      json.Value `json:"payload"`,
}
