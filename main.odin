package main

import "core:crypto"
import "core:crypto/hash"
import "core:encoding/base64"
import "core:encoding/endian"
import "core:encoding/json"
import "core:fmt"
import "core:log"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/posix"
import "rex"

GUID := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

Opcode :: enum byte {
	Continuation = 0x0,
	Text         = 0x1,
	Binary       = 0x2,
	Close        = 0x8,
	Ping         = 0x9,
	Pong         = 0xA,
}

Parse_Result :: enum {
	NeedMore,
	Ok,
	Invalid,
}

Frame :: struct {
	fin:     bool,
	opcode:  Opcode,
	payload: []byte,
}

Read_Error :: enum {
	None,
	Closed,
	IO_Error,
	Invalid_Frame,
}

encode_client_frame :: proc(f: Frame) -> [dynamic]byte {
	out: [dynamic]byte

	first := byte(f.opcode)
	if f.fin {
		first |= 0b1000_0000
	}
	append(&out, first)

	second := byte(0b1000_0000)
	n := len(f.payload)
	if n <= 125 {
		second |= byte(n)
	} else if n <= 0xFFFF {
		second |= 126
	} else {
		second |= 127
	}
	append(&out, second)

	if n > 125 && n <= 0xFFFF {
		length: [2]byte
		endian.put_u16(length[:], .Big, u16(n))
		append(&out, ..length[:])
	} else if n > 0xFFFF {
		length: [8]byte
		endian.put_u64(length[:], .Big, u64(n))
		append(&out, ..length[:])
	}

	mask: [4]byte
	crypto.rand_bytes(mask[:])
	append(&out, ..mask[:])

	for i in 0 ..< n {
		append(&out, f.payload[i] ~ mask[i % 4])
	}

	return out
}

read_server_frame :: proc(sfd: posix.FD, buf: ^[dynamic]byte) -> (frame: Frame, err: Read_Error) {
	header: [2]byte
	read_exact(sfd, header[:]) or_return

	first := header[0]
	second := header[1]

	fin := (first & 0b1000_0000) != 0
	opcode := Opcode(first & 0b0000_1111)

	length: u64
	length_code := uint(second & 0b0111_1111)
	switch length_code {
	case 0 ..= 125:
		length = u64(length_code)
	case 126:
		ext: [2]byte
		read_exact(sfd, ext[:]) or_return
		n := endian.unchecked_get_u16be(ext[:])
		length = u64(n)
	case 127:
		ext: [8]byte
		read_exact(sfd, ext[:]) or_return
		length = endian.unchecked_get_u64be(ext[:])
	}

	resize(buf, length)
	read_exact(sfd, buf[:]) or_return

	frame = Frame {
		fin     = fin,
		opcode  = opcode,
		payload = buf[:],
	}

	return frame, .None
}

read_exact :: proc(sfd: posix.FD, dst: []byte) -> Read_Error {
	offset: uint
	for offset < len(dst) {
		n := posix.recv(sfd, raw_data(dst[offset:]), len(dst) - offset, {})
		if n <= 0 {
			return .Closed
		}
		offset += uint(n)
	}
	return .None
}

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
			message_type = "hello",
			api_revision = 18,
			client       = client,
		}

		data, err := json.marshal(hello)
		if err != nil {
			log.error(err)
			os.exit(1)
		}

		frame := Frame {
			fin     = true,
			opcode  = .Text,
			payload = data,
		}
		req := encode_client_frame(frame)

		log.debug("json (%d): %s", len(data), data)
		log.debug("header: %02x", req[:2])

		posix.send(sfd, raw_data(req), len(req), {})
	}

	dynbuf: [dynamic]byte
	defer delete(dynbuf)

	for {
		frame := read_server_frame(sfd, &dynbuf) or_break
		log.debug("%s", string(frame.payload))
	}
}
