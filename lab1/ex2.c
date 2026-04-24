#include <stdio.h>
#include <sys/mman.h>   // For mmap, munmap
#include <fcntl.h>      // For open, O_RDONLY
#include <unistd.h>     // For lseek, read, close, sysconf
#include <stdlib.h>     // For exit, fprintf
#include <sys/types.h>  // For lseek, open
#include <sys/stat.h>   // For open
#define TARGET_FILE_PATH "./bin/dummy"

// foo at 0x1106
// foo size 0x4e

#define FOO_OFFSET 0x1106
#define FOO_SIZE 0x4e

int main() {

	int fd;
    void *ptr;
    ssize_t bytes_read;
    long page_size = sysconf(_SC_PAGESIZE);

    printf("Targeting file: %s\n", TARGET_FILE_PATH);

    // Open the executable file for reading
    fd = open(TARGET_FILE_PATH, O_RDONLY);
    if (fd == -1) {
        perror("Error opening target file");
        return 1;
    }

	/* Fill in the details here! */
    ptr = mmap(NULL,
                    page_size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANON,
                    -1,
                    0);

    if (ptr == MAP_FAILED){
        perror("mmap failed");
        close(fd);
        return 1;
    }
    printf("Allocated memory at: %p\n", ptr);

	/* Copy the bytes here */
    if (lseek(fd, FOO_OFFSET, SEEK_SET) == -1) {
        perror("lseek failed");
        close(fd);
        munmap(ptr, page_size);
        return 1;
    }

    bytes_read = read(fd, ptr, FOO_SIZE);
    
    if (bytes_read == -1) {
        perror("read failed");
        close(fd);
        munmap(ptr, page_size);
        return 1;
    }

    if (bytes_read != FOO_SIZE) {
        fprintf(stderr, "Error: Read %ld bytes, expected %d\n", bytes_read, FOO_SIZE);
        close(fd);
        munmap(ptr, page_size);
        return 1;
    }
    
    printf("Copied %ld bytes from file offset 0x%x\n", bytes_read, (unsigned int)FOO_OFFSET);
    close(fd);

	/* This monster casts ptr to a function pointer with no args and calls it. Basically jumps to your code. */
	(*(void(*)()) ptr)();
}
