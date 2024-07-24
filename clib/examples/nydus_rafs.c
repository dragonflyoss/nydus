#include <stdio.h>
#include "../nydus.h"

int main(int argc, char **argv)
{
    char *bootstrap = "../../tests/texture/repeatable/sha256-nocompress-repeatable";
    char *config = "version = 2\nid = \"my_id\"\n[backend]\ntype = \"localfs\"\n[backend.localfs]\ndir = \"../../tests/texture/repeatable/blobs\"\n[cache]\ntype = \"dummycache\"\n[rafs]";
    NydusFsHandle fs_handle;

    fs_handle = nydus_open_rafs(bootstrap, config);
    if (fs_handle == NYDUS_INVALID_FS_HANDLE) {
        printf("failed to open rafs filesystem from ../../tests/texture/repeatable/sha256-nocompress-repeatable\n");
        return -1;
    }

    printf("succeed to open rafs filesystem from ../../tests/texture/repeatable/sha256-nocompress-repeatable\n");
    nydus_close_rafs(fs_handle);

	return 0;
}
