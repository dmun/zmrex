package main

import "core:fmt"

Stream_Filter_State :: enum {
	// Discarding the initial binary GHOSTSNP snapshot until the first
	// ESC _ rex1;<nonce>; APC control sequence arrives.
	Skipping_Snapshot,
	// Inside a Rex APC sequence (ESC _ rex1;<nonce>;<json> ESC \),
	// discarding bytes until the ESC \ string terminator.
	In_Rex_APC,
	// Forwarding live VT output while stripping any interleaved Rex APCs.
	Live,
}

Data_Stream_Filter :: struct {
	state:         Stream_Filter_State,
	marker:        string, // "\x1b_rex1;<nonce>;"
	match_len:     int,
	esc_seen:      bool,
	snapshot_done: bool,
}

stream_filter_init :: proc(f: ^Data_Stream_Filter, nonce: u64, allocator := context.allocator) {
	f.state = .Skipping_Snapshot
	f.marker = fmt.aprintf("\x1b_rex1;%d;", nonce, allocator = allocator)
	f.match_len = 0
	f.esc_seen = false
	f.snapshot_done = false
}

stream_filter_destroy :: proc(f: ^Data_Stream_Filter) {
	delete(f.marker)
	f.marker = ""
}

// Filters a chunk from a `rex.data.terminal.v1` data stream, discarding the initial
// binary Ghostty snapshot and stripping all `ESC _ rex1;<nonce>;<json> ESC \` APC
// messages. Clean live VT bytes are appended to `out`.
stream_filter_process :: proc(f: ^Data_Stream_Filter, chunk: []byte, out: ^[dynamic]byte) {
	marker := transmute([]byte)f.marker
	if len(marker) == 0 do return

	for b in chunk {
		switch f.state {
		case .Skipping_Snapshot:
			// marker[0] is 0x1b and never recurs in marker[1:], so O(1) prefix matching is exact.
			if b == marker[f.match_len] {
				f.match_len += 1
				if f.match_len == len(marker) {
					f.match_len = 0
					f.esc_seen = false
					f.snapshot_done = true
					f.state = .In_Rex_APC
				}
			} else if b == marker[0] {
				f.match_len = 1
			} else {
				f.match_len = 0
			}

		case .In_Rex_APC:
			if f.esc_seen {
				if b == '\\' {
					f.esc_seen = false
					f.state = .Live
				} else {
					f.esc_seen = (b == 0x1b)
				}
			} else if b == 0x1b {
				f.esc_seen = true
			}

		case .Live:
			if b == marker[f.match_len] {
				f.match_len += 1
				if f.match_len == len(marker) {
					f.match_len = 0
					f.esc_seen = false
					f.state = .In_Rex_APC
				}
			} else {
				if f.match_len > 0 {
					append(out, ..marker[:f.match_len])
					f.match_len = 0
				}
				if b == marker[0] {
					f.match_len = 1
				} else {
					append(out, b)
				}
			}
		}
	}
}
