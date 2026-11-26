package ws

import "core:crypto"
import "core:crypto/hash"
import "core:encoding/base64"
import "core:fmt"
import "core:log"
import "core:strings"
import "core:sys/posix"

Error :: union {
	posix.Errno,
	Handshake_Error,
}

Handshake_Error :: enum {
	None,
	Closed,
	IO_Error,
	Invalid_Response,
	Invalid_Accept,
}

handshake :: proc(
	sfd: posix.FD,
	addr: ^posix.sockaddr,
	addr_len: posix.socklen_t,
	url: string,
	protocol: string,
) -> Error {
	log.info("Performing handshake..")

	if posix.connect(sfd, addr, addr_len) != .OK {
		return posix.errno()
	}

	raw: [16]byte
	crypto.rand_bytes(raw[:])
	key := base64.encode(raw[:])
	defer delete(key)
	log.debug("ws key:", key)

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
		url,
		key,
		protocol,
	)

	send_all(sfd, transmute([]byte)req) or_return

	log.info("Receiving..")

	// Read byte-by-byte until "\r\n\r\n" so we never over-read past the HTTP
	// upgrade headers into the first WebSocket frame.
	buf: [4096]byte
	head_len := 0
	for {
		if head_len >= len(buf) {
			return .Invalid_Response
		}
		n := posix.recv(sfd, &buf[head_len], 1, {})
		if n < 0 {
			e := posix.errno()
			if e == .EINTR do continue
			return e
		}
		if n == 0 {
			return .Closed
		}
		head_len += n
		if head_len >= 4 &&
			buf[head_len - 4] == '\r' &&
			buf[head_len - 3] == '\n' &&
			buf[head_len - 2] == '\r' &&
			buf[head_len - 1] == '\n' {
			break
		}
	}

	lines := strings.split(string(buf[:head_len]), "\r\n")
	defer delete(lines)

	accepted := false
	for line in lines[1:] {
		sep := strings.index(line, ":")
		if sep == -1 do continue

		name := strings.trim_space(line[:sep])
		value := strings.trim_space(line[sep + 1:])

		if strings.equal_fold(name, "Sec-Websocket-Accept") {
			input := strings.concatenate({key, GUID})
			defer delete(input)
			digest := hash.hash_string(.Insecure_SHA1, input)
			defer delete(digest)
			expected := base64.encode(digest)
			defer delete(expected)

			if expected != value {
				log.error("Handshake failed: invalid Sec-WebSocket-Accept")
				return .Invalid_Accept
			}

			accepted = true
			log.info("Handshake succeeded")
		}
	}

	if !accepted {
		return .Invalid_Response
	}

	return nil
}
