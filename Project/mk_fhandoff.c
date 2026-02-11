#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// Ensure complete write required: 
// Return: bytes written (>0 -> can be <len) <-> -1 error
static int write_full(int fd, const char *buf, int len) {
	int off = 0;
	int w = 0;

	while (off < len) {
		w = write(fd, buf + off, len - off);

		// got interrupted -> retries the write
		if (w < 0) {
			if (errno == EINTR)
				continue;

			return -1;
		}

		off += w;
	}

	return off;
}

// Create file (f_handoff) whose fd is sent to /proc file of the LKM:
// Exit status: 0 success <-> 1 error
int main(int argc, char *argv[]) {

	if (argc != 3) {
		errx(EXIT_FAILURE, "Usage: %s <common_path> <proc_path>\n"
		     "e.g.: %s ./file_handoff /proc/fddev", argv[0], argv[0]);
	}
	const char *f_handoff = argv[1];	// file_handoff
	const char *f_proc = argv[2];	// /proc/fddev

	// 1) File descriptor (fd) -> gets created
	// Append mode -> atomicity of the write pointer:
	int fd_handoff =
	    open(f_handoff, O_CREAT | O_RDWR | O_APPEND, 0666);
	if (fd_handoff < 0) {
		err(EXIT_FAILURE, "Error opening/creating the file %s",
		    f_handoff);
	}

	// 2) Open /proc file (/proc/fddev -> LKM):
	int fd_proc = open(f_proc, O_RDWR);
	if (fd_proc < 0) {
		err(EXIT_FAILURE, "Error opening %s", f_proc);
	}

	// 3) Parse fd (int) to string to be written in /proc/fddev
	char fd_str[12];
	snprintf(fd_str, sizeof(fd_str), "%d", fd_handoff);

	// 4) Write into /proc file (/proc/fddev -> LKM)
	// the 'fd' of the file created (f_handoff)
	// Do not use buffering (stdio) for /proc files
	// => conflicts with single-shot
	if (write_full(fd_proc, fd_str, strlen(fd_str)) <= 0) {
		close(fd_proc);
		close(fd_handoff);
		err(EXIT_FAILURE, "Error writing in %s", f_proc);
	}
	printf("File descriptor written in %s:\n%d\n", f_proc, fd_handoff);

	close(fd_proc);
	close(fd_handoff);

	exit(EXIT_SUCCESS);
}
