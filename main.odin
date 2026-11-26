package main

import "core:encoding/base64"
import "core:encoding/endian"
import "core:encoding/json"
import "core:log"
import "core:os"
import "core:path/filepath"
import "core:sys/posix"
import "rex"
import "ws"

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

connect_data :: proc(
	addr: ^posix.sockaddr,
	addr_len: posix.socklen_t,
	ticket: string,
	subprotocol: string,
) -> (
	fd: posix.FD,
	err: Error,
) {
	fd = posix.socket(.UNIX, .STREAM)
	if fd == -1 do return -1, posix.errno()
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
		return -1, ws.Read_Error.Invalid_Frame
	}
	if frame.payload[0] == 0x82 {
		log.errorf("data handshake rejected: reason 0x%02x", frame.payload[1])
		return -1, ws.Handshake_Error.Invalid_Response
	}
	if frame.payload[0] != 0x81 || len(frame.payload) != 32 {
		return -1, ws.Read_Error.Invalid_Frame
	}

	nonce := endian.unchecked_get_u64le(frame.payload[24:32])
	log.infof("data stream connected (fd=%d, nonce=%d)", fd, nonce)
	return fd, nil
}

handle_response :: proc(
	res: rex.Response,
	addr: ^posix.sockaddr,
	addr_len: posix.socklen_t,
	pollfds: ^[dynamic]posix.pollfd,
) {
	if res.id != "1" do return

	obj, _ := res.payload.(json.Object)
	tickets, _ := obj["data_tickets"].(json.Array)

	for item in tickets {
		t_obj := item.(json.Object) or_continue
		ticket := t_obj["ticket"].(json.String) or_continue
		if ticket == "" do continue

		subprotocol := t_obj["subprotocol"].(json.String) or_else "rex.data.terminal.v1"
		if subprotocol == "" do subprotocol = "rex.data.terminal.v1"

		dfd, derr := connect_data(addr, addr_len, ticket, subprotocol)
		if derr != nil {
			log.error("failed to connect data stream:", derr)
			continue
		}
		append(pollfds, posix.pollfd{fd = dfd, events = {.IN}})
	}
}

handle_control_frame :: proc(
	sfd: posix.FD,
	frame: ws.Frame,
	addr: ^posix.sockaddr,
	addr_len: posix.socklen_t,
	pollfds: ^[dynamic]posix.pollfd,
) -> Error {
	switch frame.opcode {
	case .Text:
		message := rex.decode_message(frame.payload) or_return

		switch m in message {
		case rex.Response:
			handle_response(m, addr, addr_len, pollfds)
		case rex.Event:
			log.debug(message)
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

	bootstrap := rex.Request(rex.Bootstrap_Payload) {
		message_type = "request",
		id = "1",
		method = "session.bootstrap",
		payload = {
			event_scope = "session",
			data_tickets = {
				{
					creator_name = "com.superlogical.terminal",
					data_ref_id = "terminal",
					subprotocol = "rex.data.terminal.v1",
				},
			},
		},
	}

	data = json.marshal(bootstrap) or_return
	ws.send_frame(sfd, .Text, data) or_return

	pollfds: [dynamic]posix.pollfd
	defer {
		for p in pollfds[1:] {
			posix.close(p.fd)
		}
		delete(pollfds)
	}
	append(&pollfds, posix.pollfd{fd = sfd, events = {.IN}})

	buf: [dynamic]byte
	defer delete(buf)

	poll_loop: for {
		n := posix.poll(raw_data(pollfds), posix.nfds_t(len(pollfds)), -1)
		if n < 0 {
			if posix.errno() == .EINTR {
				continue
			}
			return posix.errno()
		}

		// Control socket (index 0)
		if pollfds[0].revents != {} {
			if .ERR in pollfds[0].revents || .NVAL in pollfds[0].revents do break
			frame := ws.read_server_frame(sfd, &buf) or_break
			if frame.opcode == .Close do break
			if err := handle_control_frame(sfd, frame, addr, addr_len, &pollfds); err != nil {
				log.error("failed to parse control frame:", err)
			}
		}

		// Data sockets (index 1..)
		for i := len(pollfds) - 1; i >= 1; i -= 1 {
			p := pollfds[i]
			if p.revents == {} do continue
			if .ERR in p.revents || .NVAL in p.revents {
				posix.close(p.fd)
				unordered_remove(&pollfds, i)
				continue
			}
			frame, rerr := ws.read_server_frame(p.fd, &buf)
			if rerr != .None || frame.opcode == .Close {
				log.debugf("data stream closed (fd=%d)", p.fd)
				posix.close(p.fd)
				unordered_remove(&pollfds, i)
				continue
			}
			switch frame.opcode {
			case .Binary:
				log.debugf("data fd=%d (%d bytes)", p.fd, len(frame.payload))
				if i == 1 {
					orig: posix.termios
					posix.tcgetattr(posix.STDIN_FILENO, &orig)
					defer posix.tcsetattr(posix.STDIN_FILENO, .TCSAFLUSH, &orig)

					raw := orig
					raw.c_iflag -= {.ICRNL, .IXON, .BRKINT, .INPCK, .ISTRIP}
					raw.c_lflag -= {.ECHO, .ICANON, .ISIG, .IEXTEN}
					posix.tcsetattr(posix.STDIN_FILENO, .TCSAFLUSH, &raw)

					os.write(os.stdout, frame.payload)
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
