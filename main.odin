package main

import "base:intrinsics"
import "core:c"
import "core:encoding/base64"
import "core:encoding/endian"
import "core:encoding/json"
import "core:fmt"
import "core:log"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "rex"
import "ws"

CONTROL_POLL_IDX :: 0
STDIN_POLL_IDX   :: 1
DATA_POLL_START  :: 2
ESCAPE_TIMEOUT   :: 25 * time.Millisecond
FORMAT_MAX_BYTES :: 524288

ENTER_ALT_SCREEN :: "\x1b[?1049h\x1b[2J\x1b[H"
LEAVE_ALT_SCREEN :: "\x1b[0m\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1049l"
RESET_AND_CLEAR  :: "\x1b[0m\x1b[2J\x1b[H"

SIGWINCH :: posix.Signal(28)

when ODIN_OS == .Darwin {
	foreign import libc "system:System"
	TIOCGWINSZ :: 0x40087468
} else {
	foreign import libc "system:c"
	TIOCGWINSZ :: 0x5413
}

Winsize :: struct {
	ws_row:    u16,
	ws_col:    u16,
	ws_xpixel: u16,
	ws_ypixel: u16,
}

foreign libc {
	ioctl :: proc(fd: posix.FD, request: c.ulong, #c_vararg args: ..any) -> c.int ---
}

g_winch_received: bool

handle_sigwinch :: proc "c" (_: posix.Signal) {
	intrinsics.atomic_store(&g_winch_received, true)
}

get_terminal_size :: proc() -> (cols: int, rows: int, ok: bool) {
	wsz: Winsize
	if ioctl(posix.STDOUT_FILENO, TIOCGWINSZ, &wsz) != 0 {
		if ioctl(posix.STDIN_FILENO, TIOCGWINSZ, &wsz) != 0 {
			return 0, 0, false
		}
	}
	if wsz.ws_col == 0 || wsz.ws_row == 0 {
		return 0, 0, false
	}
	return int(wsz.ws_col), int(wsz.ws_row), true
}

write_all :: proc(fd: posix.FD, data: []byte) {
	offset: uint
	for offset < len(data) {
		n := posix.write(fd, raw_data(data[offset:]), len(data) - offset)
		if n < 0 {
			if posix.errno() == .EINTR do continue
			return
		}
		if n == 0 do return
		offset += uint(n)
	}
}

Error :: union {
	posix.Errno,
	rex.Error,
	ws.Error,
	ws.Handshake_Error,
	ws.Read_Error,
	base64.Error,
	json.Marshal_Error,
	json.Unmarshal_Error,
}

Pending_Kind :: enum {
	Bootstrap,
	Session_View,
	Data_Connect,
	Own_Block,
	Resize,
	Format,
	Blob_Read,
}

Pending_Request :: struct {
	kind:     Pending_Kind,
	block_id: string,
}

Data_Stream :: struct {
	fd:       posix.FD,
	block_id: string,
	filter:   Data_Stream_Filter,
}

Client_State :: struct {
	session_id:           string,
	focused_block_id:     string,
	view_revision:        int,
	next_req_id:          u64,
	streams:              map[posix.FD]Data_Stream,
	pending:              map[string]Pending_Request,
	format_buf:           [dynamic]byte,
	needs_initial_render: bool,
	screen_ready:         bool,
	is_tty:               bool,
}

json_as_int :: proc(v: json.Value) -> (val: int, ok: bool) {
	#partial switch n in v {
	case json.Integer:
		return int(n), true
	case json.Float:
		return int(n), true
	}
	return 0, false
}

connect_data :: proc(
	addr: ^posix.sockaddr,
	addr_len: posix.socklen_t,
	ticket: string,
	subprotocol: string,
) -> (
	fd: posix.FD,
	nonce: u64,
	err: Error,
) {
	fd = posix.socket(.UNIX, .STREAM)
	if fd == -1 do return -1, 0, posix.errno()
	defer if err != nil do posix.close(fd)

	ws.handshake(fd, addr, addr_len, "/api/data", subprotocol) or_return

	hello: [17]byte
	hello[0] = 0x01
	base64.decode_into_buf(hello[1:], ticket, base64.DEC_URL_TABLE, {.No_Padding}) or_return
	ws.send_frame(fd, .Binary, hello[:]) or_return

	buf: [dynamic]byte
	defer delete(buf)

	frame := ws.read_server_frame(fd, &buf) or_return
	if frame.opcode != .Binary || len(frame.payload) < 2 {
		return -1, 0, ws.Read_Error.Invalid_Frame
	}
	if frame.payload[0] == 0x82 {
		log.errorf("data handshake rejected: reason 0x%02x", frame.payload[1])
		return -1, 0, ws.Handshake_Error.Invalid_Response
	}
	if frame.payload[0] != 0x81 || len(frame.payload) != 32 {
		return -1, 0, ws.Read_Error.Invalid_Frame
	}

	nonce = endian.unchecked_get_u64le(frame.payload[24:32])
	log.infof("data stream connected (fd=%d, nonce=%d)", fd, nonce)
	return fd, nonce, nil
}

send_request :: proc(
	sfd: posix.FD,
	state: ^Client_State,
	method: string,
	payload: $T,
	track_kind: Maybe(Pending_Kind) = nil,
	block_id: string = "",
) -> Error {
	id_buf: [32]byte
	id := fmt.bprintf(id_buf[:], "%d", state.next_req_id)
	state.next_req_id += 1

	req := rex.Request(T) {
		message_type = "request",
		id           = id,
		method       = method,
		payload      = payload,
	}

	data := json.marshal(req) or_return
	defer delete(data)

	ws.send_frame(sfd, .Text, data) or_return

	if kind, ok := track_kind.?; ok {
		key := strings.clone(id)
		state.pending[key] = Pending_Request {
			kind     = kind,
			block_id = strings.clone(block_id) if block_id != "" else "",
		}
	}
	return nil
}

send_key :: proc(sfd: posix.FD, state: ^Client_State, key_event: rex.Key_Event) -> Error {
	if state.session_id == "" do return nil
	return send_request(
		sfd,
		state,
		"client.key",
		rex.Client_Key_Payload{session_id = state.session_id, key = key_event},
	)
}

request_own_block :: proc(sfd: posix.FD, state: ^Client_State, block_id: string) -> Error {
	block_ids := [1]string{block_id}
	return send_request(
		sfd,
		state,
		"session.own_block",
		rex.Own_Block_Payload {
			session_id = state.session_id,
			block_ids  = block_ids[:],
			mode       = "take",
		},
		.Own_Block,
		block_id,
	)
}

request_resize :: proc(
	sfd: posix.FD,
	state: ^Client_State,
	block_id: string,
	cols: int,
	rows: int,
) -> Error {
	return send_request(
		sfd,
		state,
		"com.superlogical.terminal.resize",
		rex.Block_Method_Payload(rex.Terminal_Resize_Args) {
			session_id = state.session_id,
			block_id   = block_id,
			args       = {columns = cols, rows = rows},
		},
		.Resize,
		block_id,
	)
}

request_format :: proc(sfd: posix.FD, state: ^Client_State, block_id: string) -> Error {
	return send_request(
		sfd,
		state,
		"com.superlogical.terminal.format",
		rex.Block_Method_Payload(rex.Terminal_Format_Args) {
			session_id = state.session_id,
			block_id   = block_id,
			args       = {
				format                 = "vt",
				extra_charsets         = true,
				extra_cursor           = true,
				extra_modes            = true,
				extra_scrolling_region = true,
				extra_style            = true,
				extra_tabstops         = true,
				max_bytes              = FORMAT_MAX_BYTES,
			},
		},
		.Format,
		block_id,
	)
}

request_blob_read :: proc(
	sfd: posix.FD,
	state: ^Client_State,
	block_id: string,
	blob_id: int,
	offset: int,
) -> Error {
	return send_request(
		sfd,
		state,
		"com.superlogical.terminal.blob_read",
		rex.Block_Method_Payload(rex.Terminal_Blob_Read_Args) {
			session_id = state.session_id,
			block_id   = block_id,
			args       = {id = blob_id, offset = offset, max_bytes = FORMAT_MAX_BYTES},
		},
		.Blob_Read,
		block_id,
	)
}

request_session_view :: proc(sfd: posix.FD, state: ^Client_State) -> Error {
	if state.session_id == "" do return nil
	return send_request(
		sfd,
		state,
		"session.view",
		rex.Session_View_Payload{session_id = state.session_id},
		.Session_View,
	)
}

request_data_connect :: proc(sfd: posix.FD, state: ^Client_State, block_id: string) -> Error {
	if state.session_id == "" || block_id == "" do return nil
	return send_request(
		sfd,
		state,
		"data.connect",
		rex.Data_Connect_Payload {
			session_id  = state.session_id,
			block_id    = block_id,
			data_ref_id = "terminal",
			subprotocol = "rex.data.terminal.v1",
		},
		.Data_Connect,
		block_id,
	)
}

has_stream_for_block :: proc(state: ^Client_State, block_id: string) -> bool {
	for _, &s in state.streams {
		if s.block_id == block_id do return true
	}
	return false
}

open_data_stream :: proc(
	addr: ^posix.sockaddr,
	addr_len: posix.socklen_t,
	pollfds: ^[dynamic]posix.pollfd,
	state: ^Client_State,
	block_id: string,
	ticket: string,
	subprotocol: string,
) {
	if ticket == "" do return
	sub := subprotocol if subprotocol != "" else "rex.data.terminal.v1"

	dfd, nonce, derr := connect_data(addr, addr_len, ticket, sub)
	if derr != nil {
		log.error("failed to connect data stream:", derr)
		return
	}

	ds := Data_Stream {
		fd       = dfd,
		block_id = strings.clone(block_id),
	}
	stream_filter_init(&ds.filter, nonce)
	state.streams[dfd] = ds
	append(pollfds, posix.pollfd{fd = dfd, events = {.IN}})
}

close_data_stream :: proc(state: ^Client_State, fd: posix.FD) {
	if ds, ok := &state.streams[fd]; ok {
		delete(ds.block_id)
		stream_filter_destroy(&ds.filter)
		delete_key(&state.streams, fd)
	}
	posix.close(fd)
}

extract_view_info :: proc(view: json.Object) -> (revision: int, focused_block_id: string) {
	revision, _ = json_as_int(view["revision"])
	active_win_id, _ := view["active_window_id"].(json.String)
	windows, ok := view["windows"].(json.Array)
	if !ok || len(windows) == 0 do return

	chosen: json.Object
	found := false
	for w in windows {
		w_obj := w.(json.Object) or_continue
		wid, _ := w_obj["window_id"].(json.String)
		if !found {
			chosen = w_obj
			found = true
		}
		if active_win_id != "" && wid == active_win_id {
			chosen = w_obj
			break
		}
	}
	if !found do return

	if fb, ok := chosen["focused_block_id"].(json.String); ok && fb != "" {
		return revision, fb
	}
	if zb, ok := chosen["zoomed_block_id"].(json.String); ok && zb != "" {
		return revision, zb
	}
	if layers, ok := chosen["layers"].(json.Array); ok {
		for layer in layers {
			l_obj := layer.(json.Object) or_continue
			blocks := l_obj["blocks"].(json.Array) or_continue
			for blk in blocks {
				b_obj := blk.(json.Object) or_continue
				if bid, ok := b_obj["block_id"].(json.String); ok && bid != "" {
					return revision, bid
				}
			}
		}
	}
	return revision, ""
}

extract_bootstrap_info :: proc(
	obj: json.Object,
) -> (
	session_id: string,
	revision: int,
	focused_block_id: string,
) {
	if sel, ok := obj["selected_session"].(json.Object); ok {
		if sess, ok := sel["session"].(json.Object); ok {
			if sid, ok := sess["session_id"].(json.String); ok && sid != "" {
				session_id = sid
			}
		}
		if view, ok := sel["view"].(json.Object); ok {
			if session_id == "" {
				if sid, ok := view["session_id"].(json.String); ok && sid != "" {
					session_id = sid
				}
			}
			revision, focused_block_id = extract_view_info(view)
		}
	}

	if tickets, ok := obj["data_tickets"].(json.Array); ok {
		for item in tickets {
			t_obj := item.(json.Object) or_continue
			if session_id == "" {
				if sid, ok := t_obj["session_id"].(json.String); ok && sid != "" {
					session_id = sid
				}
			}
			if focused_block_id == "" {
				if bid, ok := t_obj["block_id"].(json.String); ok && bid != "" {
					focused_block_id = bid
				}
			}
		}
	}
	return
}

set_focused_block :: proc(state: ^Client_State, block_id: string) -> bool {
	if block_id == "" || block_id == state.focused_block_id {
		return false
	}
	delete(state.focused_block_id)
	state.focused_block_id = strings.clone(block_id)
	return true
}

activate_focused_block :: proc(sfd: posix.FD, state: ^Client_State) {
	if state.session_id == "" || state.focused_block_id == "" do return

	state.screen_ready = false
	state.needs_initial_render = true
	clear(&state.format_buf)

	if state.is_tty {
		if err := request_own_block(sfd, state, state.focused_block_id); err != nil {
			log.error("failed to claim block ownership:", err)
			if ferr := request_format(sfd, state, state.focused_block_id); ferr != nil {
				log.error("failed to request terminal format:", ferr)
				state.screen_ready = true
			}
		}
	} else {
		if err := request_format(sfd, state, state.focused_block_id); err != nil {
			log.error("failed to request terminal format:", err)
			state.screen_ready = true
		}
	}
}

render_format_buffer :: proc(state: ^Client_State) {
	write_all(posix.STDOUT_FILENO, transmute([]byte)string(RESET_AND_CLEAR))
	if len(state.format_buf) > 0 {
		write_all(posix.STDOUT_FILENO, state.format_buf[:])
	}
	clear(&state.format_buf)
	state.needs_initial_render = false
	state.screen_ready = true
}

take_pending_request :: proc(state: ^Client_State, id: string) -> (req: Pending_Request, ok: bool) {
	if !(id in state.pending) do return {}, false
	key, val := delete_key(&state.pending, id)
	delete(key)
	return val, true
}

handle_response :: proc(
	sfd: posix.FD,
	res: rex.Response,
	addr: ^posix.sockaddr,
	addr_len: posix.socklen_t,
	pollfds: ^[dynamic]posix.pollfd,
	state: ^Client_State,
) {
	pending, tracked := take_pending_request(state, res.id)
	defer if tracked do delete(pending.block_id)

	if res.error.code != "" {
		log.errorf("rex request %s failed (%s): %s", res.id, res.error.code, res.error.message)
		if tracked {
			#partial switch pending.kind {
			case .Own_Block, .Resize:
				if state.needs_initial_render && pending.block_id == state.focused_block_id {
					if ferr := request_format(sfd, state, pending.block_id); ferr != nil {
						state.screen_ready = true
					}
				}
			case .Format, .Blob_Read:
				clear(&state.format_buf)
				state.needs_initial_render = false
				state.screen_ready = true
			}
		}
		return
	}

	if !tracked do return

	obj, _ := res.payload.(json.Object)

	switch pending.kind {
	case .Bootstrap:
		sid, rev, focused_bid := extract_bootstrap_info(obj)
		if sid != "" {
			delete(state.session_id)
			state.session_id = strings.clone(sid)
			log.infof("attached to session %s", state.session_id)
		}
		state.view_revision = rev

		tickets, _ := obj["data_tickets"].(json.Array)
		for item in tickets {
			t_obj := item.(json.Object) or_continue
			ticket := t_obj["ticket"].(json.String) or_continue
			bid, _ := t_obj["block_id"].(json.String)
			subprotocol, _ := t_obj["subprotocol"].(json.String)
			open_data_stream(addr, addr_len, pollfds, state, bid, ticket, subprotocol)
		}

		if set_focused_block(state, focused_bid) {
			if !has_stream_for_block(state, state.focused_block_id) {
				_ = request_data_connect(sfd, state, state.focused_block_id)
			}
			activate_focused_block(sfd, state)
		}

	case .Session_View:
		rev, focused_bid := extract_view_info(obj)
		if rev < state.view_revision do return
		state.view_revision = rev
		if set_focused_block(state, focused_bid) {
			if !has_stream_for_block(state, state.focused_block_id) {
				_ = request_data_connect(sfd, state, state.focused_block_id)
			}
			activate_focused_block(sfd, state)
		}

	case .Data_Connect:
		ticket, _ := obj["ticket"].(json.String)
		open_data_stream(addr, addr_len, pollfds, state, pending.block_id, ticket, "rex.data.terminal.v1")

	case .Own_Block:
		if pending.block_id != state.focused_block_id do return
		if cols, rows, ok := get_terminal_size(); ok {
			if rerr := request_resize(sfd, state, pending.block_id, cols, rows); rerr != nil {
				log.error("failed to resize terminal:", rerr)
				if state.needs_initial_render {
					_ = request_format(sfd, state, pending.block_id)
				}
			}
		} else if state.needs_initial_render {
			_ = request_format(sfd, state, pending.block_id)
		}

	case .Resize:
		if pending.block_id != state.focused_block_id do return
		if state.needs_initial_render {
			if ferr := request_format(sfd, state, pending.block_id); ferr != nil {
				log.error("failed to request terminal format:", ferr)
				state.screen_ready = true
			}
		}

	case .Format:
		if pending.block_id != state.focused_block_id do return
		clear(&state.format_buf)
		if content, ok := obj["content"].(json.String); ok && len(content) > 0 {
			append(&state.format_buf, ..transmute([]byte)content)
		}
		blob_id, has_id := json_as_int(obj["id"])
		eof, has_eof := obj["eof"].(json.Boolean)
		if has_id && blob_id > 0 && !(has_eof && eof) {
			if berr := request_blob_read(sfd, state, pending.block_id, blob_id, len(state.format_buf)); berr != nil {
				log.error("failed to read format blob:", berr)
				render_format_buffer(state)
			}
		} else {
			render_format_buffer(state)
		}

	case .Blob_Read:
		if pending.block_id != state.focused_block_id do return
		chunk, _ := obj["data"].(json.String)
		if len(chunk) > 0 {
			append(&state.format_buf, ..transmute([]byte)chunk)
		}
		eof, _ := obj["eof"].(json.Boolean)
		blob_id, _ := json_as_int(obj["id"])
		if !eof && blob_id > 0 && len(chunk) > 0 {
			if berr := request_blob_read(sfd, state, pending.block_id, blob_id, len(state.format_buf)); berr != nil {
				log.error("failed to read format blob:", berr)
				render_format_buffer(state)
			}
		} else {
			render_format_buffer(state)
		}
	}
}

handle_event :: proc(sfd: posix.FD, ev: rex.Event, state: ^Client_State) {
	outer, ok := ev.payload.(json.Object)
	if !ok do return

	outer_type, _ := outer["type"].(json.String)
	if outer_type != "session_event" do return

	sess_payload, ok2 := outer["payload"].(json.Object)
	if !ok2 do return

	sid, _ := sess_payload["session_id"].(json.String)
	if sid == "" || sid != state.session_id do return

	inner, ok3 := sess_payload["event"].(json.Object)
	if !ok3 do return

	ev_type, _ := inner["type"].(json.String)
	if ev_type == "session_view_changed" {
		if inner_payload, ok4 := inner["payload"].(json.Object); ok4 {
			if rev, has_rev := json_as_int(inner_payload["revision"]); has_rev && rev > state.view_revision {
				if err := request_session_view(sfd, state); err != nil {
					log.error("failed to request session.view:", err)
				}
			}
		}
	}
}

handle_control_frame :: proc(
	sfd: posix.FD,
	frame: ws.Frame,
	addr: ^posix.sockaddr,
	addr_len: posix.socklen_t,
	pollfds: ^[dynamic]posix.pollfd,
	state: ^Client_State,
) -> Error {
	switch frame.opcode {
	case .Text:
		message := rex.decode_message(frame.payload) or_return

		switch m in message {
		case rex.Response:
			handle_response(sfd, m, addr, addr_len, pollfds, state)
		case rex.Event:
			handle_event(sfd, m, state)
		case rex.Welcome:
		}
	case .Continuation:
	case .Binary:
	case .Close:
		log.debug("Closed")
	case .Ping:
		ws.send_frame(sfd, .Pong, frame.payload) or_return
	case .Pong:
	}

	return nil
}

drain_input_keys :: proc(
	sfd: posix.FD,
	state: ^Client_State,
	input_buf: ^[dynamic]byte,
	flush: bool,
	verase: byte,
) -> (
	detach: bool,
	err: Error,
) {
	offset := 0
	parse_loop: for offset < len(input_buf^) {
		text_buf: [4]byte
		res := parse_next_key(input_buf^[offset:], flush, &text_buf, verase)
		switch res.status {
		case .Incomplete:
			break parse_loop
		case .Detach:
			clear(input_buf)
			return true, nil
		case .Ignore:
			offset += res.consumed
		case .Key:
			offset += res.consumed
			send_key(sfd, state, res.event) or_return
		}
	}
	if offset > 0 {
		remove_range(input_buf, 0, offset)
	}
	return false, nil
}

attach :: proc(sfd: posix.FD, addr: ^posix.sockaddr, addr_len: posix.socklen_t) -> Error {
	// Perform handshake
	ws.handshake(sfd, addr, addr_len, "/api/control", "rex.control.v1") or_return

	// Perform Rex hello
	client := rex.Client_Info {
		kind    = "cli",
		name    = "trex",
		version = "0.1.0",
	}

	hello := rex.Hello {
		message_type = "hello",
		api_revision = 18,
		client       = client,
	}

	data := json.marshal(hello) or_return
	ws.send_frame(sfd, .Text, data) or_return
	delete(data)

	is_tty := bool(posix.isatty(posix.STDIN_FILENO))
	state := Client_State {
		next_req_id = 1,
		is_tty      = is_tty,
	}
	defer {
		delete(state.session_id)
		delete(state.focused_block_id)
		delete(state.format_buf)
		for k, v in state.pending {
			delete(k)
			delete(v.block_id)
		}
		delete(state.pending)
		for fd, &ds in state.streams {
			delete(ds.block_id)
			stream_filter_destroy(&ds.filter)
			posix.close(fd)
		}
		delete(state.streams)
	}

	send_request(
		sfd,
		&state,
		"session.bootstrap",
		rex.Bootstrap_Payload {
			event_scope = "session",
			data_tickets = {
				{
					creator_name = "com.superlogical.terminal",
					data_ref_id = "terminal",
					subprotocol = "rex.data.terminal.v1",
				},
			},
		},
		.Bootstrap,
	) or_return

	orig_termios: posix.termios
	raw_mode := false
	verase: byte = 0x7f
	if is_tty && posix.tcgetattr(posix.STDIN_FILENO, &orig_termios) == .OK {
		verase = byte(orig_termios.c_cc[.VERASE])
		raw := orig_termios
		raw.c_iflag -= {.ICRNL, .IXON, .BRKINT, .INPCK, .ISTRIP}
		raw.c_lflag -= {.ECHO, .ICANON, .ISIG, .IEXTEN}
		raw.c_cc[.VMIN] = 1
		raw.c_cc[.VTIME] = 0
		if posix.tcsetattr(posix.STDIN_FILENO, .TCSAFLUSH, &raw) == .OK {
			raw_mode = true
			write_all(posix.STDOUT_FILENO, transmute([]byte)string(ENTER_ALT_SCREEN))
		}
	}
	defer if raw_mode {
		write_all(posix.STDOUT_FILENO, transmute([]byte)string(LEAVE_ALT_SCREEN))
		posix.tcsetattr(posix.STDIN_FILENO, .TCSAFLUSH, &orig_termios)
	}

	intrinsics.atomic_store(&g_winch_received, false)
	old_winch: posix.sigaction_t
	winch_installed := false
	if is_tty {
		act: posix.sigaction_t
		act.sa_handler = handle_sigwinch
		posix.sigemptyset(&act.sa_mask)
		act.sa_flags = {}
		if posix.sigaction(SIGWINCH, &act, &old_winch) == .OK {
			winch_installed = true
		}
	}
	defer if winch_installed {
		posix.sigaction(SIGWINCH, &old_winch, nil)
	}

	pollfds: [dynamic]posix.pollfd
	defer delete(pollfds)
	append(&pollfds, posix.pollfd{fd = sfd, events = {.IN}})
	append(&pollfds, posix.pollfd{fd = posix.STDIN_FILENO, events = {.IN}})

	buf: [dynamic]byte
	defer delete(buf)

	clean_out: [dynamic]byte
	defer delete(clean_out)

	input_buf: [dynamic]byte
	defer delete(input_buf)
	input_pending_since: time.Tick

	poll_loop: for {
		if intrinsics.atomic_exchange(&g_winch_received, false) {
			if state.session_id != "" && state.focused_block_id != "" {
				if cols, rows, ok := get_terminal_size(); ok {
					if rerr := request_resize(sfd, &state, state.focused_block_id, cols, rows); rerr != nil {
						log.error("failed to resize on SIGWINCH:", rerr)
					}
				}
			}
		}

		timeout: i32 = -1
		if len(input_buf) > 0 {
			elapsed := time.tick_since(input_pending_since)
			if elapsed >= ESCAPE_TIMEOUT {
				detach, derr := drain_input_keys(sfd, &state, &input_buf, true, verase)
				if derr != nil do return derr
				if detach do break poll_loop
				continue
			}
			remaining_ms := int(time.duration_milliseconds(ESCAPE_TIMEOUT - elapsed))
			timeout = i32(max(remaining_ms, 1))
		}

		n := posix.poll(raw_data(pollfds), posix.nfds_t(len(pollfds)), timeout)
		if n < 0 {
			if posix.errno() == .EINTR {
				continue
			}
			return posix.errno()
		}

		if n == 0 && len(input_buf) > 0 {
			detach, derr := drain_input_keys(sfd, &state, &input_buf, true, verase)
			if derr != nil do return derr
			if detach do break poll_loop
			continue
		}

		// Control socket (index 0)
		if pollfds[CONTROL_POLL_IDX].revents != {} {
			if .ERR in pollfds[CONTROL_POLL_IDX].revents || .NVAL in pollfds[CONTROL_POLL_IDX].revents do break
			frame := ws.read_server_frame(sfd, &buf) or_break
			if frame.opcode == .Close do break
			if err := handle_control_frame(sfd, frame, addr, addr_len, &pollfds, &state); err != nil {
				log.error("failed to parse control frame:", err)
			}
		}

		// User input on stdin (index 1)
		if pollfds[STDIN_POLL_IDX].revents != {} {
			if .IN in pollfds[STDIN_POLL_IDX].revents {
				read_buf: [256]byte
				nr := posix.read(posix.STDIN_FILENO, raw_data(read_buf[:]), len(read_buf))
				if nr == 0 {
					if is_tty {
						break poll_loop
					}
					pollfds[STDIN_POLL_IDX].fd = -1
				} else if nr < 0 {
					e := posix.errno()
					if e != .EINTR && e != .EAGAIN {
						return e
					}
				} else {
					append(&input_buf, ..read_buf[:nr])
					detach, derr := drain_input_keys(sfd, &state, &input_buf, false, verase)
					if derr != nil do return derr
					if detach do break poll_loop
					if len(input_buf) > 0 {
						input_pending_since = time.tick_now()
					}
				}
			} else if .HUP in pollfds[STDIN_POLL_IDX].revents ||
				.ERR in pollfds[STDIN_POLL_IDX].revents ||
				.NVAL in pollfds[STDIN_POLL_IDX].revents {
				if is_tty {
					break poll_loop
				}
				pollfds[STDIN_POLL_IDX].fd = -1
			}
		}

		// Data sockets (index 2..)
		for i := len(pollfds) - 1; i >= DATA_POLL_START; i -= 1 {
			p := pollfds[i]
			if p.revents == {} do continue
			if .ERR in p.revents || .NVAL in p.revents {
				close_data_stream(&state, p.fd)
				unordered_remove(&pollfds, i)
				continue
			}
			frame, rerr := ws.read_server_frame(p.fd, &buf)
			if rerr != .None || frame.opcode == .Close {
				log.debugf("data stream closed (fd=%d)", p.fd)
				close_data_stream(&state, p.fd)
				unordered_remove(&pollfds, i)
				continue
			}
			switch frame.opcode {
			case .Binary:
				log.debugf("data fd=%d (%d bytes)", p.fd, len(frame.payload))
				if ds, ok := &state.streams[p.fd]; ok {
					clear(&clean_out)
					stream_filter_process(&ds.filter, frame.payload, &clean_out)
					if ds.block_id == state.focused_block_id && state.screen_ready && len(clean_out) > 0 {
						write_all(posix.STDOUT_FILENO, clean_out[:])
					}
				}
			case .Ping:
				ws.send_frame(p.fd, .Pong, frame.payload)
			case .Text, .Continuation, .Close, .Pong:
			}
		}
	}

	return nil
}

main :: proc() {
	when ODIN_DEBUG {
		context.logger = log.create_console_logger(.Debug)
	}

	sfd := posix.socket(.UNIX, .STREAM)
	defer posix.close(sfd)
	if sfd == -1 {
		log.error(posix.strerror(posix.errno()))
		os.exit(1)
	}

	// Get socket path
	addr: posix.sockaddr_un
	addr.sun_family = .UNIX
	#partial switch ODIN_OS {
	case .Darwin:
		data_dir, _ := os.user_data_dir(context.allocator)
		sock, _ := filepath.join({data_dir, "rex", "server.sock"})
		copy(addr.sun_path[:], sock)
	case .Linux:
		copy(addr.sun_path[:], "/run/user/1000/rex/server.sock")
	case:
		log.error("%s Not supported", ODIN_OS)
		os.exit(1)
	}

	if err := attach(sfd, (^posix.sockaddr)(&addr), size_of(addr)); err != nil {
		#partial switch e in err {
		case posix.Errno:
			log.error(posix.strerror(e))
		case:
			log.error(e)
		}
		os.exit(1)
	}
}
