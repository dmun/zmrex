package main

import "core:encoding/json"
import "core:fmt"
import "core:log"
import "core:os"
import "core:path/filepath"
import "core:sys/posix"
import "rex"
import "ws"


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

	// Perform handshake
	if err := ws.handshake(sfd, (^posix.sockaddr)(&addr), size_of(addr), "rex.control.v1");
	   err != nil {
		switch e in err {
		case posix.Errno:
			log.error(posix.strerror(e))
		case ws.Handshake_Error:
			log.error(e)
		}
		os.exit(1)
	}

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

	data, err := json.marshal(hello)
	if err != nil {
		log.error(err)
		os.exit(1)
	}

	if err := ws.send_frame(sfd, .Text, data); err != nil {
		log.error(posix.strerror(err))
		os.exit(1)
	}

	buf: [dynamic]byte
	defer delete(buf)

	for {
		frame := ws.read_server_frame(sfd, &buf) or_break

		switch frame.opcode {
		case .Text:
			message, err := rex.decode_message(frame.payload)
			if err != nil {
				log.error("failed to parse payload:", string(frame.payload))
				continue
			}
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
			if err := ws.send_frame(sfd, .Pong, frame.payload); err != nil {
				log.error(posix.strerror(posix.errno()))
			}
		case .Pong:
		}
	}
}
