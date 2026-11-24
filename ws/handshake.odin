package ws

import "core:crypto"
import "core:crypto/hash"
import "core:encoding/base64"
import "core:fmt"
import "core:log"
import "core:os"
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

handshake :: proc(sfd: posix.FD, addr: ^posix.sockaddr, addr_len: posix.socklen_t, protocol: string) -> Error {
	log.info("Performing handshake..")

	if posix.connect(sfd, addr, addr_len) != .OK {
		return posix.errno()
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
		protocol,
	)

	posix.send(sfd, &reqbuf, len(req), {})

	log.info("Receiving..")

	buf: [4096]byte
	head_len := 0
	for strings.index(string(buf[:head_len]), "\r\n\r\n") < 0 {
		n := posix.recv(sfd, raw_data(buf[head_len:]), uint(len(buf) - head_len), {})
		if n == -1 {
			err := posix.errno()
			log.error(posix.strerror(err))
			os.exit(1)
		}
		log.debug("%d bytes: %s", n, buf[:n])
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

	return nil
}
