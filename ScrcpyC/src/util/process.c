#include "process.h"

#include <assert.h>
#include <tchar.h>
//#include <libgen.h>
#include "log.h"

typedef long ssize_t;
#define CMD_MAX_LEN 8192

static bool
build_cmd(char* cmd, size_t len, const char* const argv[]) {
    // Windows command-line parsing is WTF:
    // <http://daviddeley.com/autohotkey/parameters/parameters.htm#WINPASS>
    // only make it work for this very specific program
    // (don't handle escaping nor quotes)
    size_t ret = sc_str_join(cmd, argv, ' ', len);
    if (ret >= len) {
        LOGE("Command too long (%" SC_PRIsizet " chars)", len - 1);
        return false;
    }
    return true;
}

enum sc_process_result
sc_process_execute(const char *const argv[], sc_pid *pid, unsigned flags) {
    return sc_process_execute_p(argv, pid, flags, NULL, NULL, NULL);
}

enum sc_process_result
    sc_process_execute_p(const char* const argv[], HANDLE* handle, unsigned flags,
        HANDLE* pin, HANDLE* pout, HANDLE* perr) {
    bool inherit_stdout = !pout && !(flags & SC_PROCESS_NO_STDOUT);
    bool inherit_stderr = !perr && !(flags & SC_PROCESS_NO_STDERR);

    // Add 1 per non-NULL pointer
    unsigned handle_count = !!pin
        + (pout || inherit_stdout)
        + (perr || inherit_stderr);

    enum sc_process_result ret = SC_PROCESS_ERROR_GENERIC;

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE stdin_read_handle;
    HANDLE stdout_write_handle;
    HANDLE stderr_write_handle;
    if (pin) {
        if (!CreatePipe(&stdin_read_handle, pin, &sa, 0)) {
            perror("pipe");
            return SC_PROCESS_ERROR_GENERIC;
        }
        if (!SetHandleInformation(*pin, HANDLE_FLAG_INHERIT, 0)) {
            LOGE("SetHandleInformation stdin failed");
            goto error_close_stdin;
        }
    }
    if (pout) {
        if (!CreatePipe(pout, &stdout_write_handle, &sa, 0)) {
            perror("pipe");
            goto error_close_stdin;
        }
        if (!SetHandleInformation(*pout, HANDLE_FLAG_INHERIT, 0)) {
            LOGE("SetHandleInformation stdout failed");
            goto error_close_stdout;
        }
    }
    if (perr) {
        if (!CreatePipe(perr, &stderr_write_handle, &sa, 0)) {
            perror("pipe");
            goto error_close_stdout;
        }
        if (!SetHandleInformation(*perr, HANDLE_FLAG_INHERIT, 0)) {
            LOGE("SetHandleInformation stderr failed");
            goto error_close_stderr;
        }
    }

    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    HANDLE handles[3];

    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    if (handle_count) {
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;

        unsigned i = 0;
        if (pin) {
            si.StartupInfo.hStdInput = stdin_read_handle;
            handles[i++] = si.StartupInfo.hStdInput;
        }
        if (pout || inherit_stdout) {
            si.StartupInfo.hStdOutput = pout ? stdout_write_handle
                : GetStdHandle(STD_OUTPUT_HANDLE);
            handles[i++] = si.StartupInfo.hStdOutput;
        }
        if (perr || inherit_stderr) {
            si.StartupInfo.hStdError = perr ? stderr_write_handle
                : GetStdHandle(STD_ERROR_HANDLE);
            handles[i++] = si.StartupInfo.hStdError;
        }

        SIZE_T size;
        // Call it once to know the required buffer size
        BOOL ok =
            InitializeProcThreadAttributeList(NULL, 1, 0, &size)
            || GetLastError() == ERROR_INSUFFICIENT_BUFFER;
        if (!ok) {
            goto error_close_stderr;
        }

        lpAttributeList = malloc(size);
        if (!lpAttributeList) {
            LOG_OOM();
            goto error_close_stderr;
        }

        ok = InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &size);
        if (!ok) {
            free(lpAttributeList);
            goto error_close_stderr;
        }

        ok = UpdateProcThreadAttribute(lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles, handle_count * sizeof(HANDLE),
            NULL, NULL);
        if (!ok) {
            goto error_free_attribute_list;
        }

        si.lpAttributeList = lpAttributeList;
    }

    char* cmd = malloc(CMD_MAX_LEN);
    if (!cmd || !build_cmd(cmd, CMD_MAX_LEN, argv)) {
        LOG_OOM();
        goto error_free_attribute_list;
    }
    wchar_t* wide = malloc(strlen(cmd) + 1);
    mbstowcs_s(NULL, wide, strlen(cmd) + 1, cmd, strlen(cmd));

    //wchar_t* wide = _tcsdup(cmd);
    free(cmd);
    if (!wide) {
        LOG_OOM();
        goto error_free_attribute_list;
    }

    BOOL bInheritHandles = handle_count > 0;
    // DETACHED_PROCESS to disable stdin, stdout and stderr
    DWORD dwCreationFlags = handle_count > 0 ? EXTENDED_STARTUPINFO_PRESENT
        : DETACHED_PROCESS;
   // wchar_t win_dir[8192];
    //int length = GetWindowsDirectory(win_dir,8192);
    //wchar_t* exename = wcscat(win_dir, L"\\System32\\cmd.exe");
    //wchar_t* exename = L"D:\\AndroidData\\Android\\Sdk\\platform-tools\\adb.exe";
    Sleep(1000);
    BOOL ok = CreateProcessW(NULL, wide, NULL, NULL, bInheritHandles,
        dwCreationFlags, NULL, NULL, &si.StartupInfo, &pi);
    //free(wide);
    if (!ok) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            ret = SC_PROCESS_ERROR_MISSING_BINARY;
        }
        goto error_free_attribute_list;
    }

    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        free(lpAttributeList);
    }

    // These handles are used by the child process, close them for this process
    if (pin) {
        CloseHandle(stdin_read_handle);
    }
    if (pout) {
        CloseHandle(stdout_write_handle);
    }
    if (perr) {
        CloseHandle(stderr_write_handle);
    }

    *handle = pi.hProcess;

    return SC_PROCESS_SUCCESS;

error_free_attribute_list:
    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        free(lpAttributeList);
    }
error_close_stderr:
    if (perr) {
        CloseHandle(*perr);
        CloseHandle(stderr_write_handle);
    }
error_close_stdout:
    if (pout) {
        CloseHandle(*pout);
        CloseHandle(stdout_write_handle);
    }
error_close_stdin:
    if (pin) {
        CloseHandle(*pin);
        CloseHandle(stdin_read_handle);
    }

    return ret;
}

ssize_t
sc_pipe_read_all(sc_pipe pipe, char *data, size_t len) {
    size_t copied = 0;
    while (len > 0) {
        ssize_t r = sc_pipe_read(pipe, data, len);
        if (r <= 0) {
            return copied ? (ssize_t) copied : r;
        }
        len -= r;
        data += r;
        copied += r;
    }
    return copied;
}
sc_exit_code
sc_process_wait(HANDLE handle, bool close) {
    DWORD code;
    if (WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0
        || !GetExitCodeProcess(handle, &code)) {
        // could not wait or retrieve the exit code
        code = SC_EXIT_CODE_NONE;
    }
    if (close) {
        CloseHandle(handle);
    }
    return code;
}
static int
run_observer(void *data) {
    struct sc_process_observer *observer = data;
    sc_process_wait(observer->pid, false); // ignore exit code

    sc_mutex_lock(&observer->mutex);
    observer->terminated = true;
    sc_cond_signal(&observer->cond_terminated);
    sc_mutex_unlock(&observer->mutex);

    if (observer->listener) {
        observer->listener->on_terminated(observer->listener_userdata);
    }

    return 0;
}

bool
sc_process_observer_init(struct sc_process_observer *observer, sc_pid pid,
                         const struct sc_process_listener *listener,
                         void *listener_userdata) {
    // Either no listener, or on_terminated() is defined
    assert(!listener || listener->on_terminated);

    bool ok = sc_mutex_init(&observer->mutex);
    if (!ok) {
        return false;
    }

    ok = sc_cond_init(&observer->cond_terminated);
    if (!ok) {
        sc_mutex_destroy(&observer->mutex);
        return false;
    }

    observer->pid = pid;
    observer->listener = listener;
    observer->listener_userdata = listener_userdata;
    observer->terminated = false;

    ok = sc_thread_create(&observer->thread, run_observer, "process_observer",
                          observer);
    if (!ok) {
        sc_cond_destroy(&observer->cond_terminated);
        sc_mutex_destroy(&observer->mutex);
        return false;
    }

    return true;
}

bool
sc_process_observer_timedwait(struct sc_process_observer *observer,
                              sc_tick deadline) {
    sc_mutex_lock(&observer->mutex);
    bool timed_out = false;
    while (!observer->terminated && !timed_out) {
        timed_out = !sc_cond_timedwait(&observer->cond_terminated,
                                       &observer->mutex, deadline);
    }
    bool terminated = observer->terminated;
    sc_mutex_unlock(&observer->mutex);

    return terminated;
}
void
sc_process_close(HANDLE handle) {
    bool closed = CloseHandle(handle);
    assert(closed);
    (void)closed;
}

bool
sc_process_terminate(HANDLE handle) {
    return TerminateProcess(handle, 1);
}

ssize_t
sc_pipe_read(HANDLE pipe, char* data, size_t len) {
    DWORD r;
    if (!ReadFile(pipe, data, len, &r, NULL)) {
        return -1;
    }
    return r;
}

void
sc_pipe_close(HANDLE pipe) {
    if (!CloseHandle(pipe)) {
        LOGW("Cannot close pipe");
    }
}
void
sc_process_observer_join(struct sc_process_observer *observer) {
    sc_thread_join(&observer->thread, NULL);
}

void
sc_process_observer_destroy(struct sc_process_observer *observer) {
    sc_cond_destroy(&observer->cond_terminated);
    sc_mutex_destroy(&observer->mutex);
}
