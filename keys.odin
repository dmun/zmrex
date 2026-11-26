package main

import "core:unicode/utf8"
import "rex"

DETACH_BYTE :: 0x1d // Ctrl+]

Key_Mod :: enum {
	Shift,
	Ctrl,
	Alt,
	Super,
}

Key_Mods :: bit_set[Key_Mod]

Parse_Status :: enum {
	Key,
	Detach,
	Incomplete,
	Ignore,
}

Parse_Result :: struct {
	status:   Parse_Status,
	event:    rex.Key_Event,
	consumed: int,
}

@(rodata)
KEY_LETTERS := [26]string {
	"key_a", "key_b", "key_c", "key_d", "key_e", "key_f", "key_g", "key_h", "key_i",
	"key_j", "key_k", "key_l", "key_m", "key_n", "key_o", "key_p", "key_q", "key_r",
	"key_s", "key_t", "key_u", "key_v", "key_w", "key_x", "key_y", "key_z",
}

@(rodata)
KEY_DIGITS := [10]string {
	"digit_0", "digit_1", "digit_2", "digit_3", "digit_4",
	"digit_5", "digit_6", "digit_7", "digit_8", "digit_9",
}

// Formats modifier flags in the order required by Rex's client.key API:
// shift, ctrl, alt, super.
mods_to_string :: proc(mods: Key_Mods) -> string {
	idx := 0
	if .Shift in mods do idx |= 1
	if .Ctrl in mods do idx |= 2
	if .Alt in mods do idx |= 4
	if .Super in mods do idx |= 8

	@(static, rodata)
	TABLE := [16]string {
		0  = "",
		1  = "shift",
		2  = "ctrl",
		3  = "shift+ctrl",
		4  = "alt",
		5  = "shift+alt",
		6  = "ctrl+alt",
		7  = "shift+ctrl+alt",
		8  = "super",
		9  = "shift+super",
		10 = "ctrl+super",
		11 = "shift+ctrl+super",
		12 = "alt+super",
		13 = "shift+alt+super",
		14 = "ctrl+alt+super",
		15 = "shift+ctrl+alt+super",
	}
	return TABLE[idx]
}

decode_xterm_mods :: proc(param: int) -> Key_Mods {
	if param <= 1 do return {}
	bits := param - 1
	mods: Key_Mods
	if (bits & 1) != 0 do mods += {.Shift}
	if (bits & 2) != 0 do mods += {.Alt}
	if (bits & 4) != 0 do mods += {.Ctrl}
	if (bits & 8) != 0 do mods += {.Super}
	return mods
}

ascii_key_info :: proc(b: byte) -> (key: string, unshifted: int, shifted: bool) {
	switch b {
	case 'a' ..= 'z':
		return KEY_LETTERS[b - 'a'], int(b), false
	case 'A' ..= 'Z':
		return KEY_LETTERS[b - 'A'], int(b - 'A' + 'a'), true
	case '0' ..= '9':
		return KEY_DIGITS[b - '0'], int(b), false
	case ' ':
		return "space", ' ', false
	case '`':
		return "backquote", '`', false
	case '~':
		return "backquote", '`', true
	case '!':
		return "digit_1", '1', true
	case '@':
		return "digit_2", '2', true
	case '#':
		return "digit_3", '3', true
	case '$':
		return "digit_4", '4', true
	case '%':
		return "digit_5", '5', true
	case '^':
		return "digit_6", '6', true
	case '&':
		return "digit_7", '7', true
	case '*':
		return "digit_8", '8', true
	case '(':
		return "digit_9", '9', true
	case ')':
		return "digit_0", '0', true
	case '-':
		return "minus", '-', false
	case '_':
		return "minus", '-', true
	case '=':
		return "equal", '=', false
	case '+':
		return "equal", '=', true
	case '[':
		return "bracket_left", '[', false
	case '{':
		return "bracket_left", '[', true
	case ']':
		return "bracket_right", ']', false
	case '}':
		return "bracket_right", ']', true
	case '\\':
		return "backslash", '\\', false
	case '|':
		return "backslash", '\\', true
	case ';':
		return "semicolon", ';', false
	case ':':
		return "semicolon", ';', true
	case '\'':
		return "quote", '\'', false
	case '"':
		return "quote", '\'', true
	case ',':
		return "comma", ',', false
	case '<':
		return "comma", ',', true
	case '.':
		return "period", '.', false
	case '>':
		return "period", '.', true
	case '/':
		return "slash", '/', false
	case '?':
		return "slash", '/', true
	case:
		return "unidentified", int(b), false
	}
}

make_functional_key :: proc(key: string, mods: Key_Mods = {}, action: string = "press") -> rex.Key_Event {
	return rex.Key_Event {
		key                 = key,
		mods                = mods_to_string(mods),
		consumed_mods       = "",
		text                = "",
		unshifted_codepoint = 0,
		composing           = false,
		action              = action,
	}
}

parse_single_byte :: proc(
	b: byte,
	extra_mods: Key_Mods,
	text_buf: ^[4]byte,
	verase: byte,
) -> rex.Key_Event {
	if b == 0x7f || (verase != 0 && b == verase && b == 0x08) {
		return make_functional_key("backspace", extra_mods)
	}

	switch b {
	case 0x00:
		return rex.Key_Event {
			key                 = "space",
			mods                = mods_to_string(extra_mods + {.Ctrl}),
			consumed_mods       = "",
			text                = "",
			unshifted_codepoint = ' ',
			composing           = false,
			action              = "press",
		}
	case 0x09:
		return make_functional_key("tab", extra_mods)
	case 0x0d:
		return make_functional_key("enter", extra_mods)
	case 0x01 ..= 0x08, 0x0a ..= 0x0c, 0x0e ..= 0x1a:
		letter := byte('a' + (b - 1))
		return rex.Key_Event {
			key                 = KEY_LETTERS[letter - 'a'],
			mods                = mods_to_string(extra_mods + {.Ctrl}),
			consumed_mods       = "",
			text                = "",
			unshifted_codepoint = int(letter),
			composing           = false,
			action              = "press",
		}
	case 0x1b:
		return make_functional_key("escape", extra_mods)
	case 0x1c:
		return rex.Key_Event {
			key                 = "backslash",
			mods                = mods_to_string(extra_mods + {.Ctrl}),
			consumed_mods       = "",
			text                = "",
			unshifted_codepoint = '\\',
			composing           = false,
			action              = "press",
		}
	case 0x1d:
		return rex.Key_Event {
			key                 = "bracket_right",
			mods                = mods_to_string(extra_mods + {.Ctrl}),
			consumed_mods       = "",
			text                = "",
			unshifted_codepoint = ']',
			composing           = false,
			action              = "press",
		}
	case 0x1e:
		return rex.Key_Event {
			key                 = "digit_6",
			mods                = mods_to_string(extra_mods + {.Ctrl}),
			consumed_mods       = "",
			text                = "",
			unshifted_codepoint = '6',
			composing           = false,
			action              = "press",
		}
	case 0x1f:
		return rex.Key_Event {
			key                 = "slash",
			mods                = mods_to_string(extra_mods + {.Ctrl}),
			consumed_mods       = "",
			text                = "",
			unshifted_codepoint = '/',
			composing           = false,
			action              = "press",
		}
	case 0x20 ..= 0x7e:
		key, unshifted, shifted := ascii_key_info(b)
		mods := extra_mods
		consumed: Key_Mods
		if shifted {
			mods += {.Shift}
			consumed += {.Shift}
		}
		text_buf[0] = b
		return rex.Key_Event {
			key                 = key,
			mods                = mods_to_string(mods),
			consumed_mods       = mods_to_string(consumed),
			text                = string(text_buf[:1]),
			unshifted_codepoint = unshifted,
			composing           = false,
			action              = "press",
		}
	case:
		return make_functional_key("unidentified", extra_mods)
	}
}

parse_codepoint_key :: proc(
	cp: int,
	mods: Key_Mods,
	action: string,
	text_buf: ^[4]byte,
) -> Parse_Result {
	if cp == ']' && mods == {.Ctrl} && action == "press" {
		return Parse_Result{status = .Detach}
	}

	switch cp {
	case 9:
		return Parse_Result{status = .Key, event = make_functional_key("tab", mods, action)}
	case 13:
		return Parse_Result{status = .Key, event = make_functional_key("enter", mods, action)}
	case 27:
		return Parse_Result{status = .Key, event = make_functional_key("escape", mods, action)}
	case 127:
		return Parse_Result{status = .Key, event = make_functional_key("backspace", mods, action)}
	}

	if cp >= 0x20 && cp <= 0x7e {
		key, unshifted, shifted := ascii_key_info(byte(cp))
		effective_mods := mods
		if shifted {
			effective_mods += {.Shift}
		}

		text := ""
		consumed: Key_Mods
		if !(.Ctrl in effective_mods) && !(.Super in effective_mods) {
			ch := byte(cp)
			if .Shift in effective_mods {
				consumed += {.Shift}
				if ch >= 'a' && ch <= 'z' {
					ch = ch - 'a' + 'A'
				}
			}
			text_buf[0] = ch
			text = string(text_buf[:1])
		}

		return Parse_Result {
			status = .Key,
			event = rex.Key_Event {
				key                 = key,
				mods                = mods_to_string(effective_mods),
				consumed_mods       = mods_to_string(consumed),
				text                = text,
				unshifted_codepoint = unshifted,
				composing           = false,
				action              = action,
			},
		}
	}

	if cp > 0x7e && cp <= 0x10ffff {
		text := ""
		if !(.Ctrl in mods) && !(.Super in mods) {
			encoded, n := utf8.encode_rune(rune(cp))
			copy(text_buf[:n], encoded[:n])
			text = string(text_buf[:n])
		}
		return Parse_Result {
			status = .Key,
			event = rex.Key_Event {
				key                 = "unidentified",
				mods                = mods_to_string(mods),
				consumed_mods       = "",
				text                = text,
				unshifted_codepoint = cp,
				composing           = false,
				action              = action,
			},
		}
	}

	return Parse_Result{status = .Ignore}
}

parse_csi_params :: proc(params_bytes: []byte) -> (params: [4]int, subparams: [4]int, count: int) {
	if len(params_bytes) == 0 do return

	count = 1
	in_sub := false
	for b in params_bytes {
		if b == ';' {
			if count < len(params) {
				count += 1
			}
			in_sub = false
		} else if b == ':' {
			in_sub = true
		} else if b >= '0' && b <= '9' {
			idx := count - 1
			if in_sub {
				subparams[idx] = subparams[idx] * 10 + int(b - '0')
			} else {
				params[idx] = params[idx] * 10 + int(b - '0')
			}
		}
	}
	return
}

parse_csi :: proc(
	buf: []byte,
	extra_mods: Key_Mods,
	flush: bool,
	text_buf: ^[4]byte,
) -> Parse_Result {
	// buf starts right after "\x1b["
	MAX_CSI_LEN :: 64
	final_idx := -1
	for i := 0; i < len(buf) && i < MAX_CSI_LEN; i += 1 {
		b := buf[i]
		if b >= 0x40 && b <= 0x7e {
			final_idx = i
			break
		}
		// Valid CSI parameter / intermediate bytes are 0x20..0x3f.
		if b < 0x20 || b > 0x3f {
			return Parse_Result{status = .Ignore, consumed = 2 + i + 1}
		}
	}

	if final_idx == -1 {
		if !flush && len(buf) < MAX_CSI_LEN {
			return Parse_Result{status = .Incomplete, consumed = 0}
		}
		// Timed out or malformed: emit the leading ESC and let the rest be parsed next.
		return Parse_Result {
			status   = .Key,
			event    = make_functional_key("escape", extra_mods),
			consumed = 1,
		}
	}

	total_consumed := 2 + final_idx + 1
	final_byte := buf[final_idx]
	params, subparams, pcount := parse_csi_params(buf[:final_idx])

	mods := extra_mods
	if pcount >= 2 && params[1] > 0 {
		mods += decode_xterm_mods(params[1])
	}

	action := "press"
	if pcount >= 2 && subparams[1] > 0 {
		switch subparams[1] {
		case 2:
			action = "repeat"
		case 3:
			action = "release"
		}
	}

	switch final_byte {
	case 'A':
		return Parse_Result{status = .Key, event = make_functional_key("arrow_up", mods, action), consumed = total_consumed}
	case 'B':
		return Parse_Result{status = .Key, event = make_functional_key("arrow_down", mods, action), consumed = total_consumed}
	case 'C':
		return Parse_Result{status = .Key, event = make_functional_key("arrow_right", mods, action), consumed = total_consumed}
	case 'D':
		return Parse_Result{status = .Key, event = make_functional_key("arrow_left", mods, action), consumed = total_consumed}
	case 'H':
		return Parse_Result{status = .Key, event = make_functional_key("home", mods, action), consumed = total_consumed}
	case 'F':
		return Parse_Result{status = .Key, event = make_functional_key("end", mods, action), consumed = total_consumed}
	case 'Z':
		return Parse_Result{status = .Key, event = make_functional_key("tab", mods + {.Shift}, action), consumed = total_consumed}
	case 'P':
		return Parse_Result{status = .Key, event = make_functional_key("f1", mods, action), consumed = total_consumed}
	case 'Q':
		return Parse_Result{status = .Key, event = make_functional_key("f2", mods, action), consumed = total_consumed}
	case 'R':
		return Parse_Result{status = .Key, event = make_functional_key("f3", mods, action), consumed = total_consumed}
	case 'S':
		return Parse_Result{status = .Key, event = make_functional_key("f4", mods, action), consumed = total_consumed}
	case '~':
		code := params[0]
		if code == 27 && pcount >= 3 {
			// xterm modifyOtherKeys: CSI 27 ; mod ; code ~
			res := parse_codepoint_key(params[2], mods, action, text_buf)
			res.consumed = total_consumed
			return res
		}
		key := ""
		switch code {
		case 1, 7:
			key = "home"
		case 2:
			key = "insert"
		case 3:
			key = "delete"
		case 4, 8:
			key = "end"
		case 5:
			key = "page_up"
		case 6:
			key = "page_down"
		case 11:
			key = "f1"
		case 12:
			key = "f2"
		case 13:
			key = "f3"
		case 14:
			key = "f4"
		case 15:
			key = "f5"
		case 17:
			key = "f6"
		case 18:
			key = "f7"
		case 19:
			key = "f8"
		case 20:
			key = "f9"
		case 21:
			key = "f10"
		case 23:
			key = "f11"
		case 24:
			key = "f12"
		}
		if key != "" {
			return Parse_Result{status = .Key, event = make_functional_key(key, mods, action), consumed = total_consumed}
		}
		return Parse_Result{status = .Ignore, consumed = total_consumed}
	case 'u':
		// Kitty keyboard protocol: CSI codepoint [; mods[:event_type]] u
		res := parse_codepoint_key(params[0], mods, action, text_buf)
		res.consumed = total_consumed
		return res
	case:
		return Parse_Result{status = .Ignore, consumed = total_consumed}
	}
}

parse_ss3 :: proc(b: byte, extra_mods: Key_Mods) -> Parse_Result {
	key := ""
	switch b {
	case 'A':
		key = "arrow_up"
	case 'B':
		key = "arrow_down"
	case 'C':
		key = "arrow_right"
	case 'D':
		key = "arrow_left"
	case 'H':
		key = "home"
	case 'F':
		key = "end"
	case 'P':
		key = "f1"
	case 'Q':
		key = "f2"
	case 'R':
		key = "f3"
	case 'S':
		key = "f4"
	case 'M':
		key = "numpad_enter"
	}
	if key == "" {
		return Parse_Result{status = .Ignore, consumed = 3}
	}
	return Parse_Result{status = .Key, event = make_functional_key(key, extra_mods), consumed = 3}
}

utf8_expected_len :: proc(first: byte) -> int {
	switch {
	case first < 0x80:
		return 1
	case (first & 0xe0) == 0xc0:
		return 2
	case (first & 0xf0) == 0xe0:
		return 3
	case (first & 0xf8) == 0xf0:
		return 4
	case:
		return 1
	}
}

parse_utf8_key :: proc(
	buf: []byte,
	extra_mods: Key_Mods,
	flush: bool,
	text_buf: ^[4]byte,
) -> Parse_Result {
	expected := utf8_expected_len(buf[0])
	if len(buf) < expected {
		if !flush {
			return Parse_Result{status = .Incomplete, consumed = 0}
		}
		return Parse_Result{status = .Ignore, consumed = 1}
	}

	r, size := utf8.decode_rune(buf[:expected])
	if r == utf8.RUNE_ERROR || size <= 0 {
		return Parse_Result{status = .Ignore, consumed = 1}
	}

	copy(text_buf[:size], buf[:size])
	return Parse_Result {
		status = .Key,
		event = rex.Key_Event {
			key                 = "unidentified",
			mods                = mods_to_string(extra_mods),
			consumed_mods       = "",
			text                = string(text_buf[:size]),
			unshifted_codepoint = int(r),
			composing           = false,
			action              = "press",
		},
		consumed = size,
	}
}

// Parses one keypress from the front of `buf`.
// When `flush` is false, incomplete escape or UTF-8 sequences return `.Incomplete`
// with `consumed = 0` so the caller can wait briefly for remaining bytes.
// When `flush` is true, any trailing incomplete sequence is finalized immediately.
parse_next_key :: proc(
	buf: []byte,
	flush: bool,
	text_buf: ^[4]byte,
	verase: byte = 0x7f,
) -> Parse_Result {
	if len(buf) == 0 {
		return Parse_Result{status = .Incomplete, consumed = 0}
	}

	b0 := buf[0]

	if b0 == DETACH_BYTE {
		return Parse_Result{status = .Detach, consumed = 1}
	}

	if b0 == 0x1b {
		if len(buf) == 1 {
			if !flush {
				return Parse_Result{status = .Incomplete, consumed = 0}
			}
			return Parse_Result{status = .Key, event = make_functional_key("escape"), consumed = 1}
		}

		b1 := buf[1]
		switch b1 {
		case '[':
			if len(buf) == 2 && flush {
				ev := parse_single_byte('[', {.Alt}, text_buf, verase)
				return Parse_Result{status = .Key, event = ev, consumed = 2}
			}
			return parse_csi(buf[2:], {}, flush, text_buf)
		case 'O':
			if len(buf) < 3 {
				if !flush {
					return Parse_Result{status = .Incomplete, consumed = 0}
				}
				ev := parse_single_byte('O', {.Alt}, text_buf, verase)
				return Parse_Result{status = .Key, event = ev, consumed = 2}
			}
			return parse_ss3(buf[2], {})
		case 0x1b:
			// Double ESC: either ESC ESC [ ... (Alt+CSI) or two Escape presses.
			if len(buf) >= 3 && buf[2] == '[' {
				res := parse_csi(buf[3:], {.Alt}, flush, text_buf)
				if res.status != .Incomplete {
					res.consumed += 1
				}
				return res
			}
			if len(buf) >= 3 && buf[2] == 'O' {
				if len(buf) < 4 {
					if !flush {
						return Parse_Result{status = .Incomplete, consumed = 0}
					}
					return Parse_Result{status = .Key, event = make_functional_key("escape"), consumed = 1}
				}
				res := parse_ss3(buf[3], {.Alt})
				res.consumed += 1
				return res
			}
			return Parse_Result{status = .Key, event = make_functional_key("escape"), consumed = 1}
		case:
			if b1 >= 0x80 {
				res := parse_utf8_key(buf[1:], {.Alt}, flush, text_buf)
				if res.status != .Incomplete {
					res.consumed += 1
				}
				return res
			}
			ev := parse_single_byte(b1, {.Alt}, text_buf, verase)
			return Parse_Result{status = .Key, event = ev, consumed = 2}
		}
	}

	if b0 >= 0x80 {
		return parse_utf8_key(buf, {}, flush, text_buf)
	}

	ev := parse_single_byte(b0, {}, text_buf, verase)
	return Parse_Result{status = .Key, event = ev, consumed = 1}
}
