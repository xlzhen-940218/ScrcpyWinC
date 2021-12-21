#include "command.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "config.h"
#include "common.h"
#include "util/log.h"
#include "util/str_util.h"

static const char *adb_command;

static inline const char *
get_adb_command(void) {
    if (!adb_command) {
        adb_command = getenv("ADB");
        if (!adb_command)
            adb_command = "adb";
    }
    return adb_command;
}

// serialize argv to string "[arg1], [arg2], [arg3]"
static size_t
argv_to_string(const char *const *argv, char *buf, size_t bufsize) {
    size_t idx = 0;
    bool first = true;
    while (*argv) {
        const char *arg = *argv;
        size_t len = strlen(arg);
        // count space for "[], ...\0"
        if (idx + len + 8 >= bufsize) {
            // not enough space, truncate
            assert(idx < bufsize - 4);
            memcpy(&buf[idx], "...", 3);
            idx += 3;
            break;
        }
        if (first) {
            first = false;
        } else {
            buf[idx++] = ',';
            buf[idx++] = ' ';
        }
        buf[idx++] = '[';
        memcpy(&buf[idx], arg, len);
        idx += len;
        buf[idx++] = ']';
        argv++;
    }
    assert(idx < bufsize);
    buf[idx] = '\0';
    return idx;
}

static void
show_adb_installation_msg() {
#ifndef __WINDOWS__
    static const struct {
        const char *binary;
        const char *command;
    } pkg_managers[] = {
        {"apt", "apt install adb"},
        {"apt-get", "apt-get install adb"},
        {"brew", "brew cask install android-platform-tools"},
        {"dnf", "dnf install android-tools"},
        {"emerge", "emerge dev-util/android-tools"},
        {"pacman", "pacman -S android-tools"},
    };
    for (size_t i = 0; i < ARRAY_LEN(pkg_managers); ++i) {
        if (cmd_search(pkg_managers[i].binary)) {
            LOGI("You may install 'adb' by \"%s\"", pkg_managers[i].command);
            return;
        }
    }
#endif

    LOGI("You may download and install 'adb' from "
         "https://developer.android.com/studio/releases/platform-tools");
}

static void
show_adb_err_msg(enum process_result err, const char *const argv[]) {
    char buf[512];
    switch (err) {
        case PROCESS_ERROR_GENERIC:
            argv_to_string(argv, buf, sizeof(buf));
            LOGE("Failed to execute: %s", buf);
            break;
        case PROCESS_ERROR_MISSING_BINARY:
            argv_to_string(argv, buf, sizeof(buf));
            LOGE("Command not found: %s", buf);
            LOGE("(make 'adb' accessible from your PATH or define its full"
                 "path in the ADB environment variable)");
            show_adb_installation_msg();
            break;
        case PROCESS_SUCCESS:
            // do nothing
            break;
    }
}

process_t
adb_execute_command(const char *serial, const char *const adb_cmd[], size_t len) {
    const char **cmd=malloc(len + 4);
    int i;
    process_t process;
    cmd[0] = get_adb_command();
    if (serial) {
        cmd[1] = "-s";
        cmd[2] = serial;
        i = 3;
    } else {
        i = 1;
    }

    memcpy(&cmd[i], adb_cmd, len * sizeof(const char *));
    cmd[len + i] = NULL;
    enum process_result r = cmd_execute(cmd, &process);
    if (r != PROCESS_SUCCESS) {
        show_adb_err_msg(r, cmd);
        return PROCESS_NONE;
    }
    return process;
}

process_t
adb_forward_command(const char *serial, uint16_t local_port,
            const char *device_socket_name) {
    char local[4 + 5 + 1]; // tcp:PORT
    char remote[108 + 14 + 1]; // localabstract:NAME
    sprintf(local, "tcp:%" PRIu16, local_port);
    snprintf(remote, sizeof(remote), "localabstract:%s", device_socket_name);
    const char *const adb_cmd[] = {"forward", local, remote};
    return adb_execute_command(serial, adb_cmd, ARRAY_LEN(adb_cmd));
}

process_t
adb_forward_remove_command(const char *serial, uint16_t local_port) {
    char local[4 + 5 + 1]; // tcp:PORT
    sprintf(local, "tcp:%" PRIu16, local_port);
    const char *const adb_cmd[] = {"forward", "--remove", local};
    return adb_execute_command(serial, adb_cmd, ARRAY_LEN(adb_cmd));
}

process_t
adb_reverse_command(const char *serial, const char *device_socket_name,
            uint16_t local_port) {
    char local[4 + 5 + 1]; // tcp:PORT
    char remote[108 + 14 + 1]; // localabstract:NAME
    sprintf(local, "tcp:%" PRIu16, local_port);
    snprintf(remote, sizeof(remote), "localabstract:%s", device_socket_name);
    const char *const adb_cmd[] = {"reverse", remote, local};
    return adb_execute_command(serial, adb_cmd, ARRAY_LEN(adb_cmd));
}

process_t
adb_reverse_remove_command(const char *serial, const char *device_socket_name) {
    char remote[108 + 14 + 1]; // localabstract:NAME
    snprintf(remote, sizeof(remote), "localabstract:%s", device_socket_name);
    const char *const adb_cmd[] = {"reverse", "--remove", remote};
    return adb_execute_command(serial, adb_cmd, ARRAY_LEN(adb_cmd));
}

process_t
adb_push_command(const char *serial, const char *local, const char *remote) {
#ifdef __WINDOWS__
    // Windows will parse the string, so the paths must be quoted
    // (see sys/win/command.c)
    local = strquote(local);
    if (!local) {
        return PROCESS_NONE;
    }
    remote = strquote(remote);
    if (!remote) {
        SDL_free((void *) local);
        return PROCESS_NONE;
    }
#endif

    const char *const adb_cmd[] = {"push", local, remote};
    process_t proc = adb_execute_command(serial, adb_cmd, ARRAY_LEN(adb_cmd));

#ifdef __WINDOWS__
    SDL_free((void *) remote);
    SDL_free((void *) local);
#endif

    return proc;
}

process_t
adb_install_command(const char *serial, const char *local) {
#ifdef __WINDOWS__
    // Windows will parse the string, so the local name must be quoted
    // (see sys/win/command.c)
    local = strquote(local);
    if (!local) {
        return PROCESS_NONE;
    }
#endif

    const char *const adb_cmd[] = {"install", "-r", local};
    process_t proc = adb_execute_command(serial, adb_cmd, ARRAY_LEN(adb_cmd));

#ifdef __WINDOWS__
    SDL_free((void *) local);
#endif

    return proc;
}

bool
process_check_success(process_t proc, const char *name) {
    if (proc == PROCESS_NONE) {
        LOGE("Could not execute \"%s\"", name);
        return false;
    }
    exit_code_t exit_code;
    if (!cmd_simple_wait(proc, &exit_code)) {
        
        /*if (exit_code != NO_EXIT_CODE) {
            LOGE("\"%s\" returned with value %" PRIexitcode, name, exit_code);
        } else {
            LOGE("\"%s\" exited unexpectedly", name);
        }*/
        return false;
    }
    return true;
}

static int
build_cmd(char* cmd, size_t len, const char* const argv[]) {
    // Windows command-line parsing is WTF:
    // <http://daviddeley.com/autohotkey/parameters/parameters.htm#WINPASS>
    // only make it work for this very specific program
    // (don't handle escaping nor quotes)
    size_t ret = xstrjoin(cmd, argv, ' ', len);
    if (ret >= len) {
        LOGE("Command too long (%" PRIsizet " chars)", len - 1);
        return -1;
    }
    return 0;
}

enum process_result
    cmd_execute(const char* const argv[], HANDLE* handle) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    char cmd[256];
    if (build_cmd(cmd, sizeof(cmd), argv)) {
        *handle = NULL;
        return PROCESS_ERROR_GENERIC;
    }

    wchar_t* wide = utf8_to_wide_char(cmd);
    if (!wide) {
        LOGC("Could not allocate wide char string");
        return PROCESS_ERROR_GENERIC;
    }

#ifdef WINDOWS_NOCONSOLE
    int flags = CREATE_NO_WINDOW;
#else
    int flags = 0;
#endif
    if (!CreateProcessW(NULL, wide, NULL, NULL, FALSE, flags, NULL, NULL, &si,
        &pi)) {
        SDL_free(wide);
        *handle = NULL;
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            return PROCESS_ERROR_MISSING_BINARY;
        }
        return PROCESS_ERROR_GENERIC;
    }

    SDL_free(wide);
    *handle = pi.hProcess;
    return PROCESS_SUCCESS;
}

bool
cmd_terminate(HANDLE handle) {
    return TerminateProcess(handle, 1) && CloseHandle(handle);
}

bool
cmd_simple_wait(HANDLE handle, DWORD* exit_code) {
    DWORD code;
    if (WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0
        || !GetExitCodeProcess(handle, &code)) {
        // could not wait or retrieve the exit code
        code = -1; // max value, it's unsigned
    }
    if (exit_code) {
        *exit_code = code;
    }
    return !code;
}

char*
get_executable_path(void) {
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
    return utf8_from_wide_char(buf);
}

bool
is_regular_file(const char* path) {
    wchar_t* wide_path = utf8_to_wide_char(path);
    if (!wide_path) {
        LOGC("Could not allocate wide char string");
        return false;
    }

    struct _stat path_stat;
    int r = _wstat(wide_path, &path_stat);
    SDL_free(wide_path);

    if (r) {
        perror("stat");
        return false;
    }
    return true;
}
