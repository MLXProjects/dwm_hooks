// dinject.c  -- generic x64 injector for dwm.exe
//
// Build (x64 Native Tools command prompt):
//   cl /O2 dinject.c /link /OUT:dinject.exe psapi.lib
//   (or: MSBuild hooks.sln /p:Platform=x64 /p:Configuration=Release)
//
// Usage:
//   dinject.exe -i <dllpath>   inject <dllpath> into dwm.exe
//   dinject.exe -r <dllpath>   unload <dllpath> from dwm.exe
//   dinject.exe -h             show help
//
// The tool is deliberately generic: it always targets dwm.exe and works with
// any hook DLL. Each DLL lives in its own folder (e.g. mlxghost\mlxghost.dll,
// mlxcore\mlxcore.dll); pass the path you want on the command line. dwm.exe
// is NOT a protected process (verified), so a normal LoadLibrary / FreeLibrary
// injection from an elevated process works.

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <wchar.h>

static DWORD FindPid(const wchar_t* name)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Locate an already-loaded module in a remote process by base name.
static HMODULE GetRemoteModule(HANDLE h, const wchar_t* name)
{
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(h, mods, sizeof(mods), &needed)) return NULL;
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        wchar_t buf[256];
        if (GetModuleBaseNameW(h, mods[i], buf, 256) && _wcsicmp(buf, name) == 0)
            return mods[i];
    }
    return NULL;
}

// Turn a (possibly relative) dll path into an absolute one, anchored to the
// injector's own directory, so the target process can actually find the file.
static const wchar_t* ResolveDllPath(const wchar_t* dllpath, wchar_t* out, size_t outLen)
{
    // already absolute? (X:\...  or  \\...)
    if ((wcslen(dllpath) >= 3 && dllpath[1] == L':' && dllpath[2] == L'\\') ||
        (dllpath[0] == L'\\' && dllpath[1] == L'\\')) {
        wcscpy_s(out, outLen, dllpath);
        return out;
    }
    wchar_t exe[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    wchar_t* last = wcsrchr(exe, L'\\');
    if (last) *last = L'\0';
    _snwprintf_s(out, outLen, _TRUNCATE, L"%s\\%s", exe, dllpath);
    return out;
}

static void ShowHelp(void)
{
    wprintf(L"Usage: dinject.exe <option> <dllpath>\n");
    wprintf(L"\n");
    wprintf(L"Injects into (or unloads from) the running dwm.exe process.\n");
    wprintf(L"\n");
    wprintf(L"Options:\n");
    wprintf(L"  -i <path.dll>   Inject the dll into dwm.exe.\n");
    wprintf(L"  -r <path.dll>   Release / unload the dll from dwm.exe.\n");
    wprintf(L"  -h              Show this help.\n");
    wprintf(L"\n");
    wprintf(L"Example:\n");
    wprintf(L"  dinject.exe -i mlxghost.dll\n");
    wprintf(L"  dinject.exe -r mlxghost.dll\n");
}

static int DoInject(DWORD pid, const wchar_t* dllpath)
{
    wchar_t absDll[MAX_PATH];
    const wchar_t* dll = ResolveDllPath(dllpath, absDll, MAX_PATH);

    // Only the rights we actually use; requesting PROCESS_ALL_ACCESS makes DWM's
    // DACL deny the call with ERROR_ACCESS_DENIED (5) even from an admin shell.
    HANDLE h = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                           PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, pid);
    if (!h) { wprintf(L"[!] OpenProcess failed: %lu\n", GetLastError()); return 1; }

    SIZE_T len = (wcslen(dll) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(h, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { wprintf(L"[!] VirtualAllocEx failed: %lu\n", GetLastError()); CloseHandle(h); return 1; }

    SIZE_T written = 0;
    if (!WriteProcessMemory(h, remote, dll, len, &written)) {
        wprintf(L"[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(h, remote, 0, MEM_RELEASE); CloseHandle(h); return 1;
    }

    LPTHREAD_START_ROUTINE loadLib =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW");
    HANDLE th = CreateRemoteThread(h, NULL, 0, loadLib, remote, 0, NULL);
    if (!th) { wprintf(L"[!] CreateRemoteThread failed: %lu\n", GetLastError()); CloseHandle(h); return 1; }

    WaitForSingleObject(th, INFINITE);
    DWORD status = 0;
    GetExitCodeThread(th, &status);
    if (status)
        wprintf(L"[+] Injected %s (hModule 0x%p)\n", dll, (void*)(UINT_PTR)status);
    else
        wprintf(L"[!] LoadLibrary failed for: %s  (check path exists & is x64, and DWM has no CIG)\n", dll);

    CloseHandle(th);
    CloseHandle(h);
    return status ? 0 : 1;
}

static int DoRelease(DWORD pid, const wchar_t* dllpath)
{
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
                           PROCESS_CREATE_THREAD, FALSE, pid);
    if (!h) { wprintf(L"[!] OpenProcess failed: %lu\n", GetLastError()); return 1; }

    wchar_t name[MAX_PATH];
    const wchar_t* p = wcsrchr(dllpath, L'\\');
    wcscpy_s(name, _countof(name), p ? p + 1 : dllpath);

    HMODULE hmod = GetRemoteModule(h, name);
    if (!hmod) { wprintf(L"[!] %s not loaded in target\n", name); CloseHandle(h); return 1; }

    // FreeLibrary has the right signature to be a remote thread start routine.
    LPTHREAD_START_ROUTINE freeLib = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleW(L"kernel32"), "FreeLibrary");
    HANDLE th = CreateRemoteThread(h, NULL, 0, freeLib, hmod, 0, NULL);
    if (!th) { wprintf(L"[!] CreateRemoteThread failed: %lu\n", GetLastError()); CloseHandle(h); return 1; }

    WaitForSingleObject(th, INFINITE);
    DWORD status = 0;
    GetExitCodeThread(th, &status);
    wprintf(status ? L"[+] Unloaded\n" : L"[!] FreeLibrary failed\n");

    CloseHandle(th);
    CloseHandle(h);
    return status ? 0 : 1;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3) { ShowHelp(); return 0; }

    // accept -x /x --x /x  (case-insensitive single letter)
    wchar_t flag = 0;
    if (argv[1][0] == L'-' || argv[1][0] == L'/') {
        const wchar_t* p = argv[1][1] == L'-' ? argv[1] + 2 : argv[1] + 1;
        flag = (wchar_t)towlower(p[0]);
    }
    if (flag == 0 || flag == L'h') { ShowHelp(); return 0; }

    // Always targets dwm.exe only.
    DWORD pid = FindPid(L"dwm.exe");
    if (!pid) { wprintf(L"[!] dwm.exe not found\n"); return 1; }

    if (flag == L'i') {
        return DoInject(pid, argv[2]);
    } else if (flag == L'r') {
        return DoRelease(pid, argv[2]);
    }

    ShowHelp();
    return 0;
}
