/*
 *  Copyright (C) 2004-2008 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */


#include "c-icap.h"
#include "debug.h"
#include "dlib.h"

static int isAbsolutePath(const char *file)
{
    return file[0] != '\0' && file[1] == ':' && file[2] == '\\';
}

HMODULE ci_module_load(const char *module_file, const char *default_path)
{
    HMODULE handle;
    char path[CI_MAX_PATH];
    int requiredLen;
    DWORD load_flags;

    /*Probably we should use SetDefaultDllDirectories or AddDllDirectory
      win32 API functions, and do not prepend default modules path to the
      module filename.
     */

    if (!isAbsolutePath(module_file) && default_path)
        requiredLen = snprintf(path, sizeof(path), "%s\\%s", default_path, module_file);
    else
        requiredLen = snprintf(path, sizeof(path), "%s", module_file);

    if (requiredLen >= sizeof(path)) {
        ci_debug_printf(1, "Error: to long path name, truncated to '%s'\n", path);
        return NULL;
    }

    if (isAbsolutePath(path))
        load_flags = LOAD_WITH_ALTERED_SEARCH_PATH;
    else
        load_flags = LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;

    if (!(handle = LoadLibraryEx(path, NULL, load_flags))) {
        LPTSTR lpStrMsg;
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL,
                      err,
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR) &lpStrMsg,
                      0, NULL );

        ci_debug_printf(1, "Error loading module %s:%s:%lu:%s\n",
                        module_file,
                        path,
                        err, lpStrMsg);
        LocalFree(lpStrMsg);
        return NULL;
    }
    return handle;
}

void *ci_module_sym(HMODULE handle, const char *symbol)
{
    return GetProcAddress(handle, symbol);
}


int ci_module_unload(HMODULE handle, const char *name)
{
    int ret;
    ret = FreeLibrary(handle);
    if (ret == 1) {
        ci_debug_printf(1, "Error unloading module:%s\n", name);
        return 0;
    }
    return 1;
}
