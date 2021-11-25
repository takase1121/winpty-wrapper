#ifndef WINPTY_CONPTY_H
#define WINPTY_CONPTY_H

#include <windows.h>

#include "winpty/src/include/winpty.h"

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


WINPTY_API BOOL winpty_load_conpty(winpty_error_ptr_t *err);

#endif