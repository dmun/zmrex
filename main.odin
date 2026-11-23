package main

import "core:crypto"
import "core:crypto/hash"
import "core:encoding/base64"
import "core:encoding/json"
import "core:fmt"
import "core:log"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/posix"
import "rex"

GUID := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

main :: proc() {
	when ODIN_DEBUG {
		context.logger = log.create_console_logger(.Debug)
	}

	sfd := posix.socket(.UNIX, .STREAM)
	defer posix.close(sfd)
	err := posix.errno()

	if sfd == -1 {
		log.error(posix.strerror(err))
		os.exit(1)
	}

	addr: posix.sockaddr_un
	addr.sun_family = .UNIX

	#partial switch ODIN_OS {
	case .Darwin:
		data_dir, _ := os.user_data_dir(context.allocator)
		sock, _ := filepath.join({data_dir, "rex", "server.sock"})
		copy(addr.sun_path[:], sock)
	case .Linux:
		copy(addr.sun_path[:], "/run/user/1000/rex/server.sock\x00")
	case:
		log.error("%s Not supported", ODIN_OS)
		os.exit(1)
	}

	fmt.println("connecting..")
	if posix.connect(sfd, (^posix.sockaddr)(&addr), size_of(addr)) != .OK {
		err := posix.errno()
		log.error(posix.strerror(err))
		os.exit(1)
	}

	raw: [16]byte
	crypto.rand_bytes(raw[:])
	key := base64.encode(raw[:])
	fmt.println(key)
	reqbuf: [512]byte
	req := fmt.bprintf(
		reqbuf[:],
		"GET %s HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: %s\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: %s\r\n" +
		"\r\n",
		"/api/control",
		key,
		"rex.control.v1",
	)

	posix.send(sfd, &reqbuf, len(req), {})

	fmt.println("receiving..")

	buf: [4096]byte
	head_len := 0
	for strings.index(string(buf[:head_len]), "\r\n\r\n") < 0 {
		n := posix.recv(sfd, raw_data(buf[head_len:]), uint(len(buf) - head_len), {})
		if n == -1 {
			err := posix.errno()
			log.error(posix.strerror(err))
			os.exit(1)
		}
		fmt.printfln("%d bytes: %s", n, buf[:n])
		head_len += n
	}

	lines := strings.split(string(buf[:head_len]), "\r\n")
	for line in lines[1:] {
		sep := strings.index(line, ":")
		if sep == -1 {continue}

		name := strings.trim_space(line[:sep])
		value := strings.trim_space(line[sep + 1:])

		if strings.equal_fold(name, "Sec-Websocket-Accept") {
			input := strings.concatenate({key, GUID})
			digest := hash.hash_string(.Insecure_SHA1, input)

			if base64.encode(digest) != value {
				log.error("Handshake failed")
				os.exit(1)
			}

			log.info("Handshake succeeded")
		}
	}

	{
		client := rex.Client_Info {
			kind    = "cli",
			name    = "trex",
			version = "0.1.0",
		}
		hello := rex.Hello {
			message_type = "Hello",
			api_revision = 18,
			client       = client,
		}

		data, err := json.marshal(hello)
		log.debug(string(data))
		if err != nil {
			log.error(err)
			os.exit(1)
		}
		posix.send(sfd, &data, len(data), {})
	}

	for {
		n := posix.recv(sfd, raw_data(buf[:]), len(buf), {})
		if n == 0 {
			log.info("Server closed connection")
			break
		}
		if n < 0 {
			log.error(posix.strerror(posix.errno()))
			break
		}

		for b in buf[:n] {
			fmt.printf("%02x", b)
		}
		fmt.println()
	}
}
