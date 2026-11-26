package ws

import "core:crypto"
import "core:encoding/endian"
import "core:log"
import "core:sys/posix"

GUID := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

Frame :: struct {
	fin:     bool,
	opcode:  Opcode,
	payload: []byte,
}

Opcode :: enum byte {
	Continuation = 0x0,
	Text         = 0x1,
	Binary       = 0x2,
	Close        = 0x8,
	Ping         = 0x9,
	Pong         = 0xA,
}

Read_Error :: enum {
	None,
	Closed,
	IO_Error,
	Invalid_Frame,
}

Send_Error :: enum {
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

read_raw_frame :: proc(
	sfd: posix.FD,
	buf: ^[dynamic]byte,
	append_mode: bool,
) -> (
	fin: bool,
	opcode: Opcode,
	start: int,
	err: Read_Error,
) {
	header: [2]byte
	read_exact(sfd, header[:]) or_return

	first := header[0]
	second := header[1]

	fin = (first & 0b1000_0000) != 0
	opcode = Opcode(first & 0b0000_1111)

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

	if append_mode {
		start = len(buf^)
		resize(buf, start + int(length))
	} else {
		start = 0
		resize(buf, int(length))
	}
	read_exact(sfd, buf[start:]) or_return
	return fin, opcode, start, .None
}

// Reads a complete WebSocket message, reassembling fragmented continuation frames
// and responding to interleaved Ping frames automatically.
read_server_frame :: proc(sfd: posix.FD, buf: ^[dynamic]byte) -> (frame: Frame, err: Read_Error) {
	fin, opcode, _, rerr := read_raw_frame(sfd, buf, false)
	if rerr != .None {
		return {}, rerr
	}

	if fin || opcode == .Close || opcode == .Ping || opcode == .Pong {
		return Frame{fin = fin, opcode = opcode, payload = buf[:]}, .None
	}

	// Reassemble fragmented Text/Binary message.
	ctrl_buf: [dynamic]byte
	defer delete(ctrl_buf)

	for !fin {
		cfin, cop, _, cerr := read_raw_frame(sfd, &ctrl_buf, false)
		if cerr != .None {
			return {}, cerr
		}

		#partial switch cop {
		case .Continuation:
			append(buf, ..ctrl_buf[:])
			fin = cfin
		case .Ping:
			_ = send_frame(sfd, .Pong, ctrl_buf[:])
		case .Pong:
		case .Close:
			clear(buf)
			append(buf, ..ctrl_buf[:])
			return Frame{fin = true, opcode = .Close, payload = buf[:]}, .None
		case:
			return {}, .Invalid_Frame
		}
	}

	return Frame{fin = true, opcode = opcode, payload = buf[:]}, .None
}

read_exact :: proc(sfd: posix.FD, dst: []byte) -> Read_Error {
	offset: uint
	for offset < len(dst) {
		n := posix.recv(sfd, raw_data(dst[offset:]), len(dst) - offset, {})
		if n < 0 {
			if posix.errno() == .EINTR do continue
			return .IO_Error
		}
		if n == 0 {
			return .Closed
		}
		offset += uint(n)
	}
	return .None
}

send_all :: proc(sfd: posix.FD, data: []byte) -> posix.Errno {
	offset: uint
	for offset < len(data) {
		n := posix.send(sfd, raw_data(data[offset:]), len(data) - offset, {})
		if n < 0 {
			e := posix.errno()
			if e == .EINTR do continue
			return e
		}
		offset += uint(n)
	}
	return .NONE
}

send_frame :: proc(sfd: posix.FD, opcode: Opcode, data: []byte) -> posix.Errno {
	frame := Frame {
		fin     = true,
		opcode  = opcode,
		payload = data,
	}
	req := encode_client_frame(frame)
	defer delete(req)

	log.debugf("ws send opcode=%v (%d bytes)", opcode, len(data))
	return send_all(sfd, req[:])
}
