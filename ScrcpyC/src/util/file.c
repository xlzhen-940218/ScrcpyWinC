#include "file.h"

#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include <sys/stat.h>

#include "../util/log.h"
#include "../util/str.h"

char *
sc_file_get_local_path(const char *name) {
    char *executable_path = sc_file_get_executable_path();
    if (!executable_path) {
        return NULL;
    }

    // dirname() does not work correctly everywhere, so get the parent
    // directory manually.
    // See <https://github.com/Genymobile/scrcpy/issues/2619>
    char *p = strrchr(executable_path, SC_PATH_SEPARATOR);
    if (!p) {
        LOGE("Unexpected executable path: \"%s\" (it should contain a '%c')",
             executable_path, SC_PATH_SEPARATOR);
        free(executable_path);
        return NULL;
    }

    *p = '\0'; // modify executable_path in place
    char *dir = executable_path;
    size_t dirlen = strlen(dir);
    size_t namelen = strlen(name);

    size_t len = dirlen + namelen + 2; // +2: '/' and '\0'
    char *file_path = malloc(len);
    if (!file_path) {
        LOG_OOM();
        free(executable_path);
        return NULL;
    }

    memcpy(file_path, dir, dirlen);
    file_path[dirlen] = SC_PATH_SEPARATOR;
    // namelen + 1 to copy the final '\0'
    memcpy(&file_path[dirlen + 1], name, namelen + 1);

    free(executable_path);

    return file_path;
}

char*
sc_file_get_executable_path(void) {
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) {
        return NULL;
    }
    WCHAR buf[MAX_PATH + 1]; // +1 for the null byte
    int len = GetModuleFileNameW(hModule, buf, MAX_PATH);
    if (!len) {
        return NULL;
    }
    buf[len] = '\0';
    return sc_str_from_wchars(buf);
}

bool
sc_file_is_regular(const char* path) {
    wchar_t* wide_path = sc_str_to_wchars(path);
    if (!wide_path) {
        LOG_OOM();
        return false;
    }

    struct _stat path_stat;
    int r = _wstat(wide_path, &path_stat);
    free(wide_path);

    if (r) {
        perror("stat");
        return false;
    }
    return S_ISREG(path_stat.st_mode);
    return 1;
}


