#include <wchar.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <windows.h>

#include "include/winpty.h"
#include "util.h"

// Taken from the RS5 Windows SDK, but redefined here in case we're targeting <= 17134
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define DYNLOAD_CONPTY

#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE \
	ProcThreadAttributeValue(22, FALSE, TRUE, FALSE)

typedef void *HPCON;

typedef HRESULT (*PFN_CREATE_PSEUDO_CONSOLE)(COORD size, HANDLE input, HANDLE output, DWORD flags, HPCON *con);
typedef HRESULT (*PFN_RESIZE_PSEUDO_CONSOLE)(HPCON con, COORD size);
typedef void (*PFN_CLOSE_PSEUDO_CONSOLE)(HPCON *con);

static PFN_CREATE_PSEUDO_CONSOLE CreatePseudoConsole = NULL;
static PFN_RESIZE_PSEUDO_CONSOLE ResizePseudoConsole = NULL;
static PFN_CLOSE_PSEUDO_CONSOLE ClosePseudoConsole = NULL;
#endif

struct winpty_error_s {
	winpty_result_t code;
	LPCWSTR cstr;
	LPWSTR dstr;
};

struct winpty_config_s {
	COORD size;
	int mouse_mode;
};

struct winpty_s {
	HPCON con;
	LPWSTR conin_name, conout_name, conerr_name;
	HANDLE thread, proc, wait, conin, conout, conerr;
	CRITICAL_SECTION mutex;
};

struct winpty_spawn_config_s {
	LPWSTR appname, cmdline, cwd, env;
	UINT64 flag;
};

#define PROC_LIST_SIZE 64

static volatile long pipe_number;

static struct winpty_error_s E_OUT_OF_MEMORY = {
	WINPTY_ERROR_OUT_OF_MEMORY,
	L"Out of memory",
	NULL
};

static LPCWSTR E_UNSPECIFIED = L"Unspecified error";

// ERROR HANDLING
static winpty_error_ptr_t winpty_error_new(int code, DWORD rc, LPCWSTR msg) {
	if (code == WINPTY_ERROR_OUT_OF_MEMORY)
		return &E_OUT_OF_MEMORY;

	winpty_error_ptr_t err = calloc(1, sizeof(winpty_error_t));
	if (msg != NULL && rc != ERROR_SUCCESS) {
		// print descriptive error messages
		LPWSTR win_err = win32_error(rc);
		if (win_err == NULL)
			goto out_of_memory;

		int new_len = wcslen(msg) + wcslen(win_err) + 3; // including ": "
		LPWSTR new_str = malloc(sizeof(WCHAR) * new_len);
		if (new_str == NULL)
			goto out_of_memory;

		swprintf(new_str, new_len, L"%ls: %ls", msg, win_err);
		LocalFree(win_err);

		err->dstr = new_str;
	} else if (msg != NULL) {
		err->dstr = strdup_w(msg);
	} else if (rc != ERROR_SUCCESS) {
		err->dstr = win32_error(rc);
	} else {
		err->cstr = E_UNSPECIFIED;
	}

	return err;

out_of_memory:
	if (err->dstr != NULL) free(err->dstr);
	free(err);
	return &E_OUT_OF_MEMORY;
}

#define THROW(code, rc, msg) 					\
	if (err != NULL)							\
		*err = winpty_error_new(code, rc, msg)

WINPTY_API winpty_result_t winpty_error_code(winpty_error_ptr_t err) {
	return err != NULL ? err->code : WINPTY_ERROR_SUCCESS;
}

WINPTY_API LPCWSTR winpty_error_msg(winpty_error_ptr_t err) {
	return err->cstr == NULL ? err->dstr : err->cstr;
}

WINPTY_API void winpty_error_free(winpty_error_ptr_t err) {
	if (err == NULL) return;
	if (err->dstr != NULL) free(err->dstr);
	if (err->code != WINPTY_ERROR_OUT_OF_MEMORY) free(err);
}


// LOADING CONPTY
static DWORD load_conpty() {
#ifdef DYNLOAD_CONPTY
	HMODULE lib = LoadLibrary("kernel32.dll");
	if (lib == NULL)
		return GetLastError();

	CreatePseudoConsole = (PFN_CREATE_PSEUDO_CONSOLE) GetProcAddress(lib, "CreatePseudoConsole");
	if (CreatePseudoConsole == NULL)
		return GetLastError();

	ResizePseudoConsole = (PFN_RESIZE_PSEUDO_CONSOLE) GetProcAddress(lib, "ResizePseudoConsole");
	if (ResizePseudoConsole == NULL)
		return GetLastError();

	ClosePseudoConsole = (PFN_CLOSE_PSEUDO_CONSOLE) GetProcAddress(lib, "ClosePseudoConsole");
	if (ClosePseudoConsole == NULL)
		return GetLastError();
#endif
	return ERROR_SUCCESS;
}


// NON-STANDARD API
WINPTY_API BOOL winpty_load_conpty(winpty_error_ptr_t *err) {
	DWORD rc = load_conpty();
	if (rc != ERROR_SUCCESS)
		THROW(WINPTY_ERROR_UNSPECIFIED, rc, L"cannot load conpty");
	return rc == ERROR_SUCCESS;
}


// WINPTY CONFIG
WINPTY_API winpty_config_t *winpty_config_new(UINT64 agentFlags, winpty_error_ptr_t *err) {
	assert(load_conpty() == ERROR_SUCCESS);
	winpty_config_t *config = calloc(1, sizeof(winpty_config_t));
	if (config == NULL) {
		THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
		return NULL;
	}
	return config;
}

WINPTY_API void winpty_config_free(winpty_config_t *config) {
	free(config);
}

WINPTY_API void winpty_config_set_initial_size(winpty_config_t *config, int cols, int rows) {
	config->size.X = cols;
	config->size.Y = rows;
}

WINPTY_API void winpty_config_set_mouse_mode(winpty_config_t *config, int mode) {
	config->mouse_mode = mode;
}

WINPTY_API void winpty_config_set_agent_timeout(winpty_config_t *config, DWORD timeout) {}


// STARTING PTYs
static HANDLE create_pipe(LPWSTR *pipe_name) {
	*pipe_name = malloc(sizeof(WCHAR) * MAX_PATH);
	if (*pipe_name == NULL)
		return INVALID_HANDLE_VALUE;

	swprintf(*pipe_name, MAX_PATH, L"\\\\.\\pipe\\conpty-pipe.%08lx.%08lx", GetCurrentProcessId(), InterlockedIncrement(&pipe_number));
	return CreateNamedPipeW(
		*pipe_name,
		PIPE_ACCESS_INBOUND | PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		0,
		0,
		30000,
		NULL
	);
}

WINPTY_API winpty_t *winpty_open(const winpty_config_t *config, winpty_error_ptr_t *err) {
	winpty_t *pty = calloc(1, sizeof(winpty_t));
	if (pty == NULL) {
		THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
		return NULL;
	}

	InitializeCriticalSection(&pty->mutex);

	HANDLE conin = create_pipe(&pty->conin_name);
	if (conin == INVALID_HANDLE_VALUE) {
		if (pty->conin_name == NULL)
			THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
		else
			THROW(WINPTY_ERROR_UNSPECIFIED, GetLastError(), L"cannot create stdin pipe");
		goto cleanup;
	}

	HANDLE conout = create_pipe(&pty->conout_name);
	if (conout == INVALID_HANDLE_VALUE) {
		if (pty->conout_name == NULL)
			THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
		else
			THROW(WINPTY_ERROR_UNSPECIFIED, GetLastError(), L"cannot create stdout pipe");
		goto cleanup;
	}

	HANDLE conerr = create_pipe(&pty->conerr_name);
	if (conerr == INVALID_HANDLE_VALUE) {
		if (pty->conerr_name == NULL)
			THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
		else
			THROW(WINPTY_ERROR_UNSPECIFIED, GetLastError(), L"cannot create stderr pipe");
		goto cleanup;
	}

	pty->conin = conin;
	pty->conout = conout;
	pty->conerr = conerr;
	pty->wait = INVALID_HANDLE_VALUE;

	HRESULT hr = CreatePseudoConsole(
		config->size,
		conin,
		conout,
		0,
		&pty->con
	);

	if (FAILED(hr)) {
		THROW(WINPTY_ERROR_UNSPECIFIED, HRESULT_CODE(hr), L"cannot create pty");
		goto cleanup;
	}

	return pty;

cleanup:
	if (conin != INVALID_HANDLE_VALUE) CloseHandle(conin);
	if (conout != INVALID_HANDLE_VALUE) CloseHandle(conout);
	if (conerr != INVALID_HANDLE_VALUE) CloseHandle(conerr);
	DeleteCriticalSection(&pty->mutex);
	if (pty != NULL) free(pty);

	return NULL;
}

WINPTY_API HANDLE winpty_agent_process(winpty_t *pty) {
	ASSERT(pty != NULL);
	return INVALID_HANDLE_VALUE;
}


// PIPES
WINPTY_API LPCWSTR winpty_conin_name(winpty_t *pty) {
	return pty->conin_name;
}

WINPTY_API LPCWSTR winpty_conout_name(winpty_t *pty) {
	return pty->conout_name;
}

WINPTY_API LPCWSTR winpty_conerr_name(winpty_t *pty) {
	return pty->conerr_name;
}


// ACTUALLY STARTING PROCESSES
WINPTY_API winpty_spawn_config_t *winpty_spawn_config_new(
	UINT64 flag,
	LPCWSTR appname,
	LPCWSTR cmdline,
	LPCWSTR cwd,
	LPCWSTR env,
	winpty_error_ptr_t *err
) {
	winpty_spawn_config_t *config = malloc(sizeof(winpty_spawn_config_t));
	if (config == NULL) {
		THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
		return NULL;
	}

	config->flag = flag;
	config->appname = appname != NULL ? strdup_w(appname) : NULL;
	config->cmdline = cmdline != NULL ? strdup_w(cmdline) : NULL;
	config->cwd = cwd != NULL ? strdup_w(cwd) : NULL;
	config->env = env != NULL ? strdup_w(env) : NULL;

	return config;
}

WINPTY_API void winpty_spawn_config_free(winpty_spawn_config_t *config) {
	if (config->appname != NULL) free(config->appname);
	if (config->cmdline != NULL) free(config->cmdline);
	if (config->cwd != NULL) free(config->cwd);
	if (config->env != NULL) free(config->env);
	free(config);
}

static void close_pty(winpty_t *pty) {
	ClosePseudoConsole(pty->con);
	// try to flush named pipe
	if (pty->conout != INVALID_HANDLE_VALUE) {
		FlushFileBuffers(pty->conout);
		DisconnectNamedPipe(pty->conout);
		CloseHandle(pty->conout);
	}

	if (pty->conerr != INVALID_HANDLE_VALUE) {
		DisconnectNamedPipe(pty->conerr);
		CloseHandle(pty->conerr);
	}

	if (pty->conin != INVALID_HANDLE_VALUE) {
		DisconnectNamedPipe(pty->conin);
		CloseHandle(pty->conin);
	}
	CloseHandle(pty->thread);
	CloseHandle(pty->proc);

	pty->conin = INVALID_HANDLE_VALUE;
	pty->conout = INVALID_HANDLE_VALUE;
	pty->conerr = INVALID_HANDLE_VALUE;
	pty->thread = INVALID_HANDLE_VALUE;
	pty->proc = INVALID_HANDLE_VALUE;
}

VOID CALLBACK auto_shutdown_cb(PVOID param, BOOLEAN expired) {
	winpty_t *pty = (winpty_t *) param;
	EnterCriticalSection(&pty->mutex);
	close_pty(pty);
	LeaveCriticalSection(&pty->mutex);
}

WINPTY_API BOOL winpty_spawn(
	winpty_t *pty,
	const winpty_spawn_config_t *config,
	HANDLE *process_handle,
	HANDLE *thread_handle,
	DWORD *create_process_error,
	winpty_error_ptr_t *err
) {
	EnterCriticalSection(&pty->mutex);

	ConnectNamedPipe(pty->conin, NULL);
	ConnectNamedPipe(pty->conout, NULL);

	BOOL res = FALSE;
	STARTUPINFOEXW si = { 0 };
	si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
	si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
	si.StartupInfo.hStdError = NULL;
	si.StartupInfo.hStdInput = NULL;
	si.StartupInfo.hStdOutput = NULL;

	SIZE_T sz = 0;
	InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
	BYTE *attrlist = malloc(sz);
	if (attrlist == NULL) {
		THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
		return FALSE;
	}

	si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) attrlist;
	res = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &sz);
	if (!res) {
		THROW(WINPTY_ERROR_UNSPECIFIED, GetLastError(), L"InitializeProcThreadAttributeList failed");
		goto cleanup;
	}

	res = UpdateProcThreadAttribute(
		si.lpAttributeList,
		0,
		PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		pty->con,
		sizeof(HPCON),
		NULL,
		NULL
	);
	if (!res) {
		THROW(WINPTY_ERROR_UNSPECIFIED, GetLastError(), L"UpdateProcThreadAttribute failed");
		goto cleanup;
	}

	PROCESS_INFORMATION pi = { 0 };
	res = CreateProcessW(
		config->appname,
		config->cmdline,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
		config->env,
		config->cwd,
		&si.StartupInfo,
		&pi
	);
	if (!res) {
		THROW(WINPTY_ERROR_SPAWN_CREATE_PROCESS_FAILED, 0, L"CreateProcessW failed");
		if (create_process_error != NULL)
			*create_process_error = GetLastError();
		goto cleanup;
	}

	if (config->flag & WINPTY_SPAWN_FLAG_AUTO_SHUTDOWN != 0) {
		res = RegisterWaitForSingleObject(
			&pty->wait,
			pi.hProcess,
			&auto_shutdown_cb,
			(PVOID) pty,
			INFINITE,
			WT_EXECUTEONLYONCE | WT_EXECUTELONGFUNCTION
		);
		if (!res) {
			THROW(WINPTY_ERROR_UNSPECIFIED, GetLastError(), L"RegisterWaitForSingleObject failed");
			goto cleanup;
		}
	}

	if (process_handle != NULL) *process_handle = pi.hProcess;
	if (thread_handle != NULL) *thread_handle = pi.hThread;
	pty->proc = pi.hProcess;
	pty->thread = pi.hThread;

	LeaveCriticalSection(&pty->mutex);

	return TRUE;

cleanup:
	DeleteProcThreadAttributeList(si.lpAttributeList);
	free(si.lpAttributeList);

	LeaveCriticalSection(&pty->mutex);

	return FALSE;
}

WINPTY_API void winpty_free(winpty_t *pty) {
	EnterCriticalSection(&pty->mutex);

	if (pty->wait != INVALID_HANDLE_VALUE)
		UnregisterWait(pty->wait);

	GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, GetProcessId(pty->proc));
	TerminateProcess(pty->proc, 0);

	WaitForSingleObject(pty->proc, INFINITE);
	close_pty(pty);

	LeaveCriticalSection(&pty->mutex);
	DeleteCriticalSection(&pty->mutex);

	free(pty->conin_name);
	free(pty->conout_name);
	free(pty->conerr_name);
	free(pty);
}


// OTHERS
WINPTY_API BOOL winpty_set_size(winpty_t *pty, int cols, int rows, winpty_error_ptr_t *err) {
	COORD size = { cols, rows };
	HRESULT hr = ResizePseudoConsole(pty->con, size);
	if (FAILED(hr)) {
		THROW(WINPTY_ERROR_UNSPECIFIED, HRESULT_CODE(hr), L"cannot resize pty");
		return FALSE;
	}
	return TRUE;
}

WINPTY_API int winpty_get_console_process_list(winpty_t *pty, int *process_list, const int process_count, winpty_error_ptr_t *err) {
	DWORD *plist = calloc(PROC_LIST_SIZE, sizeof(DWORD));
	if (plist == NULL) {
		THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
		return 0;
	}

	DWORD actual_count = GetConsoleProcessList(plist, PROC_LIST_SIZE);
	if (actual_count > PROC_LIST_SIZE) {
		plist = realloc(plist, actual_count);
		if (plist == NULL) {
			THROW(WINPTY_ERROR_OUT_OF_MEMORY, 0, NULL);
			return 0;
		}
		actual_count = GetConsoleProcessList(plist, actual_count);
	}

	for (DWORD i = 0; i < (actual_count > process_count ? process_count : actual_count); i++)
		process_list[i] = plist[i];

	return actual_count;
}