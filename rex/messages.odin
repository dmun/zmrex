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

Data_Ticket_Request :: struct {
	creator_name: string `json:"creator_name"`,
	data_ref_id:  string `json:"data_ref_id"`,
	subprotocol:  string `json:"subprotocol,omitempty"`,
}

Bootstrap_Payload :: struct {
	event_scope:          string `json:"event_scope"`,
	preferred_session_id: string `json:"preferred_session_id,omitempty"`,
	attach_session_ids:   []string `json:"attach_session_ids,omitempty"`,
	data_tickets:         []Data_Ticket_Request `json:"data_tickets,omitempty"`,
}

Attach_Payload :: struct {
	session_id: string `json:"session_id"`,
}

Key_Event :: struct {
	key:                 string `json:"key"`,
	mods:                string `json:"mods"`,
	consumed_mods:       string `json:"consumed_mods"`,
	text:                string `json:"text"`,
	unshifted_codepoint: int    `json:"unshifted_codepoint"`,
	composing:           bool   `json:"composing"`,
	action:              string `json:"action"`,
}

Client_Key_Payload :: struct {
	session_id: string    `json:"session_id"`,
	key:        Key_Event `json:"key"`,
	block_id:   string    `json:"block_id,omitempty"`,
	prefix:     []string  `json:"prefix,omitempty"`,
}

Own_Block_Payload :: struct {
	session_id: string   `json:"session_id"`,
	block_ids:  []string `json:"block_ids,omitempty"`,
	mode:       string   `json:"mode,omitempty"`,
}

Session_View_Payload :: struct {
	session_id: string `json:"session_id"`,
}

Data_Connect_Payload :: struct {
	session_id:  string `json:"session_id"`,
	block_id:    string `json:"block_id"`,
	data_ref_id: string `json:"data_ref_id"`,
	subprotocol: string `json:"subprotocol,omitempty"`,
}

Block_Method_Payload :: struct($T: typeid) {
	session_id: string `json:"session_id"`,
	block_id:   string `json:"block_id"`,
	args:       T      `json:"args"`,
}

Terminal_Resize_Args :: struct {
	columns: int `json:"columns"`,
	rows:    int `json:"rows"`,
}

Terminal_Format_Args :: struct {
	format:                 string `json:"format,omitempty"`,
	extra_charsets:         bool   `json:"extra_charsets,omitempty"`,
	extra_cursor:           bool   `json:"extra_cursor,omitempty"`,
	extra_modes:            bool   `json:"extra_modes,omitempty"`,
	extra_scrolling_region: bool   `json:"extra_scrolling_region,omitempty"`,
	extra_style:            bool   `json:"extra_style,omitempty"`,
	extra_tabstops:         bool   `json:"extra_tabstops,omitempty"`,
	max_bytes:              int    `json:"max_bytes,omitempty"`,
}

Terminal_Blob_Read_Args :: struct {
	id:        int `json:"id"`,
	offset:    int `json:"offset"`,
	max_bytes: int `json:"max_bytes,omitempty"`,
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
