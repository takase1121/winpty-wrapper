#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <wchar.h>
#include <windows.h>

// UTILS
static LPWSTR strdup_w(LPCWSTR str) {
	LPWSTR new_str = malloc(sizeof(WCHAR) * (wcslen(str) + 1));
	if (new_str == NULL)
		return NULL;

	wcscpy(new_str, str);
	return new_str;
}

static LPWSTR win32_error(DWORD rc) {
	LPWSTR msg = NULL;
	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER
		| FORMAT_MESSAGE_FROM_SYSTEM
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		rc,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR) &msg,
		0,
		NULL
	);

	return msg;
}

#define ASSERT(cond)																	\
	do {																				\
		if (!(cond)) {																	\
			fprintf(stderr, "assertion failed (%s:%s): %s", __FILE__, __LINE__, #cond);	\
			assert(FALSE && #cond);														\
			abort();																	\
		}																				\
	} while (0)

#endif