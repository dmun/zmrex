package main

import "core:testing"

@(test)
test_stream_filter_skips_snapshot_and_strips_rex_apcs :: proc(t: ^testing.T) {
	f: Data_Stream_Filter
	stream_filter_init(&f, 12345)
	defer stream_filter_destroy(&f)

	out: [dynamic]byte
	defer delete(out)

	// Binary GHOSTSNP snapshot followed by initial resize APC, theme APC, live text,
	// another resize APC, and more live VT text.
	payload :=
		"GHOSTSNP\x01\x00\x00\x00binary\x1b_not_rex\x1b\\garbage" +
		"\x1b_rex1;12345;{\"type\":\"resize\",\"cols\":80,\"rows\":24}\x1b\\" +
		"\x1b_rex1;12345;{\"type\":\"theme\"}\x1b\\" +
		"\x1b[32mhello\x1b[0m" +
		"\x1b_rex1;12345;{\"type\":\"resize\",\"cols\":100,\"rows\":30}\x1b\\" +
		" world\r\n"

	stream_filter_process(&f, transmute([]byte)string(payload), &out)
	testing.expect(t, f.snapshot_done, "snapshot should be marked complete")
	testing.expect_value(t, string(out[:]), "\x1b[32mhello\x1b[0m world\r\n")
}

@(test)
test_stream_filter_handles_byte_by_byte_splits :: proc(t: ^testing.T) {
	f: Data_Stream_Filter
	stream_filter_init(&f, 99)
	defer stream_filter_destroy(&f)

	out: [dynamic]byte
	defer delete(out)

	// Feed 1 byte at a time to test every possible chunk boundary split
	// (including split marker, split ESC \, and wrong-nonce spoofed APCs).
	payload :=
		"GHOSTSNP\x00\x01\x02" +
		"\x1b_rex1;99;{\"type\":\"resize\"}\x1b\\" +
		"prompt$ " +
		"\x1b_rex1;999;{\"type\":\"spoofed\"}\x1b\\" +
		"\x1b_rex1;99;{\"type\":\"child_exited\",\"exit_code\":0}\x1b\\" +
		"done"

	raw := transmute([]byte)string(payload)
	for i in 0 ..< len(raw) {
		stream_filter_process(&f, raw[i:i + 1], &out)
	}

	testing.expect(t, f.snapshot_done, "snapshot should be marked complete")
	// Spoofed nonce (999) must pass through untouched; real nonce (99) must be stripped.
	testing.expect_value(t, string(out[:]), "prompt$ \x1b_rex1;999;{\"type\":\"spoofed\"}\x1b\\done")
}
