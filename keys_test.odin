package main

import "core:encoding/json"
import "core:testing"
import "rex"

@(test)
test_parse_printable_ascii :: proc(t: ^testing.T) {
	text_buf: [4]byte

	// Lowercase letter
	res := parse_next_key(transmute([]byte)string("a"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 1)
	testing.expect_value(t, res.event.key, "key_a")
	testing.expect_value(t, res.event.mods, "")
	testing.expect_value(t, res.event.consumed_mods, "")
	testing.expect_value(t, res.event.text, "a")
	testing.expect_value(t, res.event.unshifted_codepoint, int('a'))
	testing.expect_value(t, res.event.composing, false)
	testing.expect_value(t, res.event.action, "press")

	// Uppercase letter
	res = parse_next_key(transmute([]byte)string("Z"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.event.key, "key_z")
	testing.expect_value(t, res.event.mods, "shift")
	testing.expect_value(t, res.event.consumed_mods, "shift")
	testing.expect_value(t, res.event.text, "Z")
	testing.expect_value(t, res.event.unshifted_codepoint, int('z'))

	// Shifted punctuation
	res = parse_next_key(transmute([]byte)string("!"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.event.key, "digit_1")
	testing.expect_value(t, res.event.mods, "shift")
	testing.expect_value(t, res.event.consumed_mods, "shift")
	testing.expect_value(t, res.event.text, "!")
	testing.expect_value(t, res.event.unshifted_codepoint, int('1'))

	// Space
	res = parse_next_key(transmute([]byte)string(" "), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.event.key, "space")
	testing.expect_value(t, res.event.text, " ")
	testing.expect_value(t, res.event.unshifted_codepoint, int(' '))
}

@(test)
test_parse_control_and_detach :: proc(t: ^testing.T) {
	text_buf: [4]byte

	// Ctrl+G (matches rex/API.md example)
	res := parse_next_key([]byte{0x07}, false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 1)
	testing.expect_value(t, res.event.key, "key_g")
	testing.expect_value(t, res.event.mods, "ctrl")
	testing.expect_value(t, res.event.consumed_mods, "")
	testing.expect_value(t, res.event.text, "")
	testing.expect_value(t, res.event.unshifted_codepoint, int('g'))
	testing.expect_value(t, res.event.action, "press")

	// Ctrl+C
	res = parse_next_key([]byte{0x03}, false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.event.key, "key_c")
	testing.expect_value(t, res.event.mods, "ctrl")
	testing.expect_value(t, res.event.unshifted_codepoint, int('c'))

	// Enter, Tab, Backspace
	res = parse_next_key([]byte{'\r'}, false, &text_buf)
	testing.expect_value(t, res.event.key, "enter")
	testing.expect_value(t, res.event.mods, "")
	testing.expect_value(t, res.event.text, "")
	testing.expect_value(t, res.event.unshifted_codepoint, 0)

	res = parse_next_key([]byte{'\t'}, false, &text_buf)
	testing.expect_value(t, res.event.key, "tab")

	res = parse_next_key([]byte{0x7f}, false, &text_buf)
	testing.expect_value(t, res.event.key, "backspace")

	// Detach on Ctrl+]
	res = parse_next_key([]byte{0x1d}, false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Detach)
	testing.expect_value(t, res.consumed, 1)
}

@(test)
test_parse_escape_and_sequences :: proc(t: ^testing.T) {
	text_buf: [4]byte

	// Bare ESC waits when flush=false, emits escape when flush=true
	res := parse_next_key([]byte{0x1b}, false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Incomplete)
	testing.expect_value(t, res.consumed, 0)

	res = parse_next_key([]byte{0x1b}, true, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 1)
	testing.expect_value(t, res.event.key, "escape")

	// Arrow Up (CSI)
	res = parse_next_key(transmute([]byte)string("\x1b[A"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 3)
	testing.expect_value(t, res.event.key, "arrow_up")
	testing.expect_value(t, res.event.mods, "")

	// Ctrl+Shift+Right (CSI 1;6C) - verify modifier order: shift+ctrl
	res = parse_next_key(transmute([]byte)string("\x1b[1;6C"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 6)
	testing.expect_value(t, res.event.key, "arrow_right")
	testing.expect_value(t, res.event.mods, "shift+ctrl")

	// Delete (CSI 3~)
	res = parse_next_key(transmute([]byte)string("\x1b[3~"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 4)
	testing.expect_value(t, res.event.key, "delete")

	// Shift+Tab (CSI Z)
	res = parse_next_key(transmute([]byte)string("\x1b[Z"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 3)
	testing.expect_value(t, res.event.key, "tab")
	testing.expect_value(t, res.event.mods, "shift")

	// F1 (SS3 P)
	res = parse_next_key(transmute([]byte)string("\x1bOP"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 3)
	testing.expect_value(t, res.event.key, "f1")

	// Alt+a
	res = parse_next_key(transmute([]byte)string("\x1ba"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 2)
	testing.expect_value(t, res.event.key, "key_a")
	testing.expect_value(t, res.event.mods, "alt")
	testing.expect_value(t, res.event.consumed_mods, "")
	testing.expect_value(t, res.event.text, "a")
	testing.expect_value(t, res.event.unshifted_codepoint, int('a'))

	// Alt+Ctrl+x
	res = parse_next_key([]byte{0x1b, 0x18}, false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 2)
	testing.expect_value(t, res.event.key, "key_x")
	testing.expect_value(t, res.event.mods, "ctrl+alt")
	testing.expect_value(t, res.event.unshifted_codepoint, int('x'))

	// CSI u (Kitty keyboard protocol): Ctrl+I
	res = parse_next_key(transmute([]byte)string("\x1b[105;5u"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 8)
	testing.expect_value(t, res.event.key, "key_i")
	testing.expect_value(t, res.event.mods, "ctrl")
	testing.expect_value(t, res.event.text, "")
	testing.expect_value(t, res.event.unshifted_codepoint, int('i'))

	// CSI u detach: Ctrl+]
	res = parse_next_key(transmute([]byte)string("\x1b[93;5u"), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Detach)
	testing.expect_value(t, res.consumed, 7)

	// Alt+[ waits when flush=false, resolves to alt+bracket_left when flush=true
	res = parse_next_key(transmute([]byte)string("\x1b["), false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Incomplete)
	res = parse_next_key(transmute([]byte)string("\x1b["), true, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 2)
	testing.expect_value(t, res.event.key, "bracket_left")
	testing.expect_value(t, res.event.mods, "alt")
	testing.expect_value(t, res.event.text, "[")
}

@(test)
test_parse_utf8 :: proc(t: ^testing.T) {
	text_buf: [4]byte

	// Complete UTF-8 rune 'é' (0xc3 0xa9)
	res := parse_next_key([]byte{0xc3, 0xa9}, false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Key)
	testing.expect_value(t, res.consumed, 2)
	testing.expect_value(t, res.event.key, "unidentified")
	testing.expect_value(t, res.event.text, "é")
	testing.expect_value(t, res.event.unshifted_codepoint, int('é'))

	// Partial UTF-8 waits when flush=false
	res = parse_next_key([]byte{0xc3}, false, &text_buf)
	testing.expect_value(t, res.status, Parse_Status.Incomplete)
	testing.expect_value(t, res.consumed, 0)
}

@(test)
test_client_key_json_serialization :: proc(t: ^testing.T) {
	req := rex.Request(rex.Client_Key_Payload) {
		message_type = "request",
		id           = "2",
		method       = "client.key",
		payload      = {
			session_id = "session:123",
			key = rex.Key_Event {
				key                 = "key_g",
				mods                = "ctrl",
				consumed_mods       = "",
				text                = "",
				unshifted_codepoint = 103,
				composing           = false,
				action              = "press",
			},
		},
	}

	data, err := json.marshal(req)
	testing.expect_value(t, err, nil)
	defer delete(data)

	// Verify all required key fields are present even when zero/empty/false
	parsed, perr := json.parse(data)
	testing.expect_value(t, perr, json.Error.None)
	defer json.destroy_value(parsed)

	root := parsed.(json.Object)
	testing.expect_value(t, root["type"].(json.String), "request")
	testing.expect_value(t, root["id"].(json.String), "2")
	testing.expect_value(t, root["method"].(json.String), "client.key")

	payload := root["payload"].(json.Object)
	testing.expect_value(t, payload["session_id"].(json.String), "session:123")
	_, has_block_id := payload["block_id"]
	testing.expect(t, !has_block_id, "block_id should be omitted when empty")
	_, has_prefix := payload["prefix"]
	testing.expect(t, !has_prefix, "prefix should be omitted when nil")

	key := payload["key"].(json.Object)
	testing.expect_value(t, key["key"].(json.String), "key_g")
	testing.expect_value(t, key["mods"].(json.String), "ctrl")
	testing.expect_value(t, key["consumed_mods"].(json.String), "")
	testing.expect_value(t, key["text"].(json.String), "")
	testing.expect_value(t, key["unshifted_codepoint"].(json.Float), 103.0)
	testing.expect_value(t, key["composing"].(json.Boolean), false)
	testing.expect_value(t, key["action"].(json.String), "press")
}
