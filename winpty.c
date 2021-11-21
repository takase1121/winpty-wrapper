#include <stdlib.h>
#include <assert.h>
#include <windows.h>

#include "winpty.h"

#define PROC_LIST_SIZE 64

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

static volatile long pipe_number;


// ERROR HANDLING
static LPCWSTR error_strings[] = {
	L"Operation sucess",
	L"Out of memory",
	L"CreateProcess failed",
	L"Connection to the agent is lost",
	L"winpty-agent.exe is missing",
	L"Unknown error",
	L"winpty-agent.exe died",
	L"Connection timeout",
	L"Cannot start winpty-agent.exe",
};

struct winpty_error_s {
	winpty_result_t code;
	LPCWSTR str;
};

static winpty_error_ptr_t winpty_error_new(int code) {
	winpty_error_ptr_t err = malloc(sizeof(winpty_error_t));
	err->str = error_strings[code];
	err->code = code;
	return err;
}

WINPTY_API winpty_result_t winpty_error_code(winpty_error_ptr_t err) {
	return err->code;
}

WINPTY_API LPCWSTR winpty_error_msg(winpty_error_ptr_t err) {
	return err->str;
}

WINPTY_API void winpty_error_free(winpty_error_ptr_t err) {
	if (err != NULL) free(err);
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
WINPTY_API void winpty_load_conpty() {
	assert(load_conpty() == ERROR_SUCCESS);
}


// WINPTY CONFIG
struct winpty_config_s {
	COORD size;
	int mouse_mode;
};

WINPTY_API winpty_config_t *winpty_config_new(UINT64 agentFlags, winpty_error_ptr_t *err) {
	assert(load_conpty() == ERROR_SUCCESS);
	winpty_config_t *config = calloc(1, sizeof(winpty_config_t));
	if (config == NULL)
		*err = winpty_error_new(WINPTY_ERROR_OUT_OF_MEMORY);
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
struct winpty_s {
	HPCON con;
	LPWSTR conin_name, conout_name, conerr_name;
	HANDLE thread, proc;
};

static HANDLE create_pipe(LPWSTR *pipe_name) {
	*pipe_name = malloc(sizeof(WCHAR) * MAX_PATH);
	if (*pipe_name == NULL)
		return INVALID_HANDLE_VALUE;

	wsprintfW(*pipe_name, L"\\\\.\\pipe\\conpty-pipe.%08lx.%08lx", GetCurrentProcessId(), InterlockedIncrement(&pipe_number));
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
		*err = winpty_error_new(WINPTY_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

	HANDLE conin = create_pipe(&pty->conin_name);
	if (conin == INVALID_HANDLE_VALUE) {
		*err = winpty_error_new(pty->conin_name == NULL ? WINPTY_ERROR_OUT_OF_MEMORY : WINPTY_ERROR_UNSPECIFIED);
		goto cleanup;
	}

	HANDLE conout = create_pipe(&pty->conout_name);
	if (conout == INVALID_HANDLE_VALUE) {
		*err = winpty_error_new(pty->conout_name == NULL ? WINPTY_ERROR_OUT_OF_MEMORY : WINPTY_ERROR_UNSPECIFIED);
		goto cleanup;
	}

	HANDLE conerr = create_pipe(&pty->conerr_name);
	if (conerr == INVALID_HANDLE_VALUE) {
		*err = winpty_error_new(pty->conerr_name == NULL ? WINPTY_ERROR_OUT_OF_MEMORY : WINPTY_ERROR_UNSPECIFIED);
		goto cleanup;
	}

	HRESULT hr = CreatePseudoConsole(
		config->size,
		conin,
		conout,
		0,
		&pty->con
	);

	if (FAILED(hr)) {
		*err = winpty_error_new(WINPTY_ERROR_UNSPECIFIED);
		goto cleanup;
	}

	return pty;

cleanup:
	if (conin != INVALID_HANDLE_VALUE) CloseHandle(conin);
	if (conout != INVALID_HANDLE_VALUE) CloseHandle(conout);
	if (conerr != INVALID_HANDLE_VALUE) CloseHandle(conerr);
	if (pty != NULL) free(pty);

	return NULL;
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
struct winpty_spawn_config_s {
	LPWSTR appname, cmdline, cwd, env;
};

static LPWSTR strdup_w(LPCWSTR str) {
	LPWSTR new_str = malloc(sizeof(WCHAR) * (wcslen(str) + 1));
	if (new_str == NULL)
		return NULL;

	wcscpy(new_str, str);
	return new_str;
}

WINPTY_API winpty_spawn_config_t *winpty_spawn_config_new(
	UINT64 flags,
	LPCWSTR appname,
	LPCWSTR cmdline,
	LPCWSTR cwd,
	LPCWSTR env,
	winpty_error_ptr_t *err
) {
	winpty_spawn_config_t *config = malloc(sizeof(winpty_spawn_config_t));
	if (config == NULL) {
		*err = winpty_error_new(WINPTY_ERROR_OUT_OF_MEMORY);
		return NULL;
	}

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

WINPTY_API BOOL winpty_spawn(
	winpty_t *pty,
	const winpty_spawn_config_t *config,
	HANDLE *process_handle,
	HANDLE *thread_handle,
	DWORD *create_process_error,
	winpty_error_ptr_t *err
) {
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
		*err = winpty_error_new(WINPTY_ERROR_OUT_OF_MEMORY);
		return FALSE;
	}

	si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) attrlist;
	res = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &sz);
	if (!res) {
		*err = winpty_error_new(WINPTY_ERROR_UNSPECIFIED);
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
		*err = winpty_error_new(WINPTY_ERROR_UNSPECIFIED);
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
		*err = winpty_error_new(WINPTY_ERROR_SPAWN_CREATE_PROCESS_FAILED);
		if (create_process_error != NULL)
			*create_process_error = GetLastError();
	}

	*process_handle = pi.hProcess;
	*thread_handle = pi.hThread;
	pty->thread = pi.hProcess;
	pty->proc = pi.hProcess;

	return TRUE;

cleanup:
	DeleteProcThreadAttributeList(si.lpAttributeList);
	free(si.lpAttributeList);

	return FALSE;
}

WINPTY_API void winpty_free(winpty_t *pty) {
	CloseHandle(pty->thread);
	CloseHandle(pty->proc);
	ClosePseudoConsole(pty->con);
	free(pty->conin_name);
	free(pty->conout_name);
	free(pty->conerr_name);
	free(pty);
}


// OTHERS
WINPTY_API BOOL winpty_set_size(winpty_t *pty, int cols, int rows, winpty_error_ptr_t *err) {
	COORD size = { cols, rows };
	if (FAILED(ResizePseudoConsole(pty->con, size))) {
		*err = winpty_error_new(WINPTY_ERROR_UNSPECIFIED);
		return FALSE;
	}
	return TRUE;
}

WINPTY_API int winpty_get_console_process_list(winpty_t *pty, int *process_list, const int process_count, winpty_error_ptr_t *err) {
	DWORD *plist = calloc(PROC_LIST_SIZE, sizeof(DWORD));
	if (plist == NULL) {
		*err = winpty_error_new(WINPTY_ERROR_OUT_OF_MEMORY);
		return 0;
	}

	DWORD actual_count = GetConsoleProcessList(plist, PROC_LIST_SIZE);
	if (actual_count > PROC_LIST_SIZE) {
		plist = realloc(plist, actual_count);
		if (plist == NULL) {
			*err = winpty_error_new(WINPTY_ERROR_OUT_OF_MEMORY);
			return 0;
		}
		actual_count = GetConsoleProcessList(plist, actual_count);
	}

	for (DWORD i = 0; i < (actual_count > process_count ? process_count : actual_count); i++)
		process_list[i] = plist[i];

	return actual_count;
}