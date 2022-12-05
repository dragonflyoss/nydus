#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Magic number for Nydus file handle.
 */
#define NYDUS_FILE_HANDLE_MAGIC 17148644263605784967ull

/**
 * Value representing an invalid Nydus file handle.
 */
#define NYDUS_INVALID_FILE_HANDLE 0

/**
 * Magic number for Nydus filesystem handle.
 */
#define NYDUS_FS_HANDLE_MAGIC 17148643159786606983ull

/**
 * Value representing an invalid Nydus filesystem handle.
 */
#define NYDUS_INVALID_FS_HANDLE 0

/**
 * Handle representing a Nydus file object.
 */
typedef uintptr_t NydusFileHandle;

/**
 * Handle representing a Nydus filesystem object.
 */
typedef uintptr_t NydusFsHandle;

/**
 * Open the file with `path` in readonly mode.
 *
 * The `NydusFileHandle` returned should be freed by calling `nydus_close()`.
 */
NydusFileHandle nydus_fopen(NydusFsHandle fs_handle, const char *path);

/**
 * Close the file handle returned by `nydus_fopen()`.
 */
void nydus_fclose(NydusFileHandle handle);

/**
 * Open a RAFS filesystem and return a handle to the filesystem object.
 *
 * The returned filesystem handle should be freed by calling `nydus_close_rafs()`, otherwise
 * it will cause memory leak.
 */
NydusFsHandle nydus_open_rafs(const char *bootstrap, const char *config);

/**
 * Open a RAFS filesystem with default configuration and return a handle to the filesystem object.
 *
 * The returned filesystem handle should be freed by calling `nydus_close_rafs()`, otherwise
 * it will cause memory leak.
 */
NydusFsHandle nydus_open_rafs_default(const char *bootstrap, const char *dir_path);

/**
 * Close the RAFS filesystem returned by `nydus_open_rafs()` and friends.
 *
 * All `NydusFileHandle` objects created from the `NydusFsHandle` should be freed before calling
 * `nydus_close_rafs()`, otherwise it may cause panic.
 */
void nydus_close_rafs(NydusFsHandle handle);
