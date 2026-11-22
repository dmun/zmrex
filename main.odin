package main

import "core:fmt"
import "core:os"
import "core:sys/posix"

main :: proc() {
	sfd := posix.socket(.UNIX, .STREAM)
	defer posix.close(sfd)
	err := posix.errno()

	if sfd == -1 {
		fmt.eprintln(posix.strerror(err))
		os.exit(1)
	}

	addr: posix.sockaddr_un
	addr.sun_family = .UNIX
	copy(addr.sun_path[:], "/run/user/1000/rex/server.sock\x00")

	fmt.println("connecting..")
	if posix.connect(sfd, (^posix.sockaddr)(&addr), size_of(addr)) != .OK {
		err := posix.errno()
		fmt.eprintln(posix.strerror(err))
		os.exit(1)
	}

	buf: [4096]byte

	fmt.println("receiving..")
	n := posix.recv(sfd, &buf, size_of(buf), {})
	if n == -1 {
		err := posix.errno()
		fmt.eprintln(posix.strerror(err))
		os.exit(1)
	}

	fmt.printfln("%d bytes: %s",n , buf[:n])

	// if posix.bind(sfd, (^posix.sockaddr)(&addr), size_of(addr)) != .OK {
	// 	err := posix.errno()
	// 	fmt.eprintln(posix.strerror(err))
	// 	os.exit(1)
	// }

	fmt.println(sfd)
}
