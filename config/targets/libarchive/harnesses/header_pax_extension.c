#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <archive.h>
#include <archive_entry.h>

int main(int argc, char **argv) {
    __AFL_FUZZ_INIT();
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 8 || len > 512 * 1024) continue;
        struct archive *a = archive_read_new();
        if (!a) continue;
        archive_read_support_format_tar(a);
        archive_read_support_filter_all(a);
        if (archive_read_open_memory(a, buf, len) == ARCHIVE_OK) {
            struct archive_entry *entry;
            while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
                archive_entry_pathname(entry);
                archive_entry_pathname_w(entry);
                archive_entry_size(entry);
                archive_entry_mtime(entry);
                archive_entry_mode(entry);
                char data_buf[4096];
                ssize_t r;
                while ((r = archive_read_data(a, data_buf, sizeof(data_buf))) > 0) ;
            }
        }
        archive_read_free(a);
    }
    return 0;
}