package rex

import "core:encoding/json"
import "core:log"

Message :: union {
	Event,
	Response,
	Welcome,
}

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
	client:           Client_Info `json:"client,omitempty"`,
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
	// message_type:        string `json:"type"`,
	protocol:            string `json:"protocol"`,
	limits:              Welcome_Limits `json:"limits"`,
	carriers:            []Carrier `json:"carriers,omitempty"`,
	client:              Welcome_Client `json:"client,omitempty"`,
	features:            []string `json:"features,omitempty"`,
	api_revision:        int `json:"api_revision,omitempty"`,
	api_server_revision: int `json:"api_server_revision,omitempty"`,
	api_min_revision:    int `json:"api_min_revision,omitempty"`,
}

Request :: struct($T: typeid) {
	message_type: string `json:"type"`,
	id:           string `json:"id"`,
	method:       string `json:"method"`,
	payload:      T `json:"payload,omitempty"`,
}

Bootstrap_Payload :: struct {
	event_scope:          string `json:"event_scope"`,
	preferred_session_id: string `json:"preferred_session_id,omitempty"`,
	attach_session_ids:   []string `json:"attach_session_ids,omitempty"`,
}

Attach_Payload :: struct {
	session_id: string `json:"session_id"`,
}

Error :: struct {
	code:    string `json:"code"`,
	message: string `json:"message"`,
	status:  int `json:"status"`,
}

Response :: struct {
	id:      string `json:"id"`,
	seq:     int `json:"seq"`,
	payload: json.Value `json:"payload,omitempty"`,
	error:   Error `json:"error,omitempty"`,
}

Event :: struct {
	// message_type: string `json:"type"`,
	seq:     int `json:"seq"`,
	payload: json.Value `json:"payload"`,
}

unmarshal_as :: proc(
	$T: typeid,
	data: []byte,
	allocator := context.allocator,
) -> (
	msg: Message,
	err: json.Unmarshal_Error,
) {
	v: T
	json.unmarshal(data, &v, allocator = allocator) or_return
	return v, nil
}

decode_message :: proc(data: []byte) -> (msg: Message, err: json.Unmarshal_Error) {
	Header :: struct {
		message_type: string `json:"type"`,
	}

	header: Header
	json.unmarshal(data, &header) or_return

	switch header.message_type {
	case "welcome":
		return unmarshal_as(Welcome, data)
	case "response":
		return unmarshal_as(Response, data)
	case "event":
		return unmarshal_as(Event, data)
	}

	return nil, nil
}
