package main

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
	json.Marshal_Error,
	json.Unmarshal_Error,
}

handle_frame :: proc(sfd: posix.FD, frame: ws.Frame) -> Error {
	switch frame.opcode {
	case .Text:
		message := rex.decode_message(frame.payload) or_return
		log.debug(message)

		switch m in message {
		case rex.Response:
		case rex.Event:
		case rex.Welcome:
		}
	case .Continuation:
	case .Binary:
	case .Close:
		log.debug("Closed")
		break
	case .Ping:
		ws.send_frame(sfd, .Pong, frame.payload) or_return
	case .Pong:
	}

	return nil
}

attach :: proc(sfd: posix.FD, addr: ^posix.sockaddr, addr_len: posix.socklen_t) -> Error {
	// Perform handshake
	ws.handshake(sfd, addr, addr_len, "rex.control.v1") or_return

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
		payload = {event_scope = "session"},
	}

	data = json.marshal(bootstrap) or_return
	ws.send_frame(sfd, .Text, data) or_return

	buf: [dynamic]byte
	defer delete(buf)

	for {
		frame := ws.read_server_frame(sfd, &buf) or_break
		if err := handle_frame(sfd, frame); err != nil {
			log.error("failed to parse frame:", frame)
			continue
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
