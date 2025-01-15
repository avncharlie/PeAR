/* IF YOU CHANGE THIS FILE, UPDATE TRACE_REWRITER WITH THE NEW SYMBOLS FOR THE
 * DRY RUN VERSION OF THE REWRITER
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

extern char cov_file_prefix;
int is_setup = 0;

#define MAX_FNAME 0x100
char cov_file[MAX_FNAME];

int fd;

// Fast implementation that doesn't open and close file on every trace.
// However, some data may be lost if the program abnormally terminates.
void track_cov_fast(int block_id) {
    if (!is_setup) {
        // generate log file name
        snprintf(cov_file, MAX_FNAME, "%s.%d.cov", &cov_file_prefix, getpid());
        // try and open log file
        fd = open(cov_file, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (fd < 0) {
            printf("error opening log file \"%s\"\n", cov_file);
            exit(1);
        }
        is_setup = 1;
    }

    // some data may get lost in kernel buffer ... rip
    write(fd, &block_id, 4);

}

// Slow implementation that open and close file on every trace.
// No data loss, except for the final block that triggers an abnormal exit.
void track_cov_slow(int block_id) {
    if (!is_setup) {
        snprintf(cov_file, MAX_FNAME, "%s.%d.cov", &cov_file_prefix, getpid());
        is_setup = 1;
    }

    int fd = open(cov_file, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) {
        printf("error opening log file \"%s\"\n", cov_file);
        exit(1);
    }
    write(fd, &block_id, 4);
    close(fd);
}
