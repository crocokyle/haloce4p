#include <windows.h>

namespace {

HMODULE g_real_version = nullptr;
INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT;

using FnGetFileVersionInfoA = BOOL(WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID);
using FnGetFileVersionInfoByHandle = BOOL(WINAPI*)(DWORD, HANDLE, DWORD, LPVOID);
using FnGetFileVersionInfoExA = BOOL(WINAPI*)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
using FnGetFileVersionInfoExW = BOOL(WINAPI*)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
using FnGetFileVersionInfoSizeA = DWORD(WINAPI*)(LPCSTR, LPDWORD);
using FnGetFileVersionInfoSizeExA = DWORD(WINAPI*)(DWORD, LPCSTR, LPDWORD);
using FnGetFileVersionInfoSizeExW = DWORD(WINAPI*)(DWORD, LPCWSTR, LPDWORD);
using FnGetFileVersionInfoSizeW = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
using FnGetFileVersionInfoW = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID);
using FnVerFindFileA = DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
using FnVerFindFileW = DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
using FnVerInstallFileA = DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
using FnVerInstallFileW = DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
using FnVerLanguageNameA = DWORD(WINAPI*)(DWORD, LPSTR, DWORD);
using FnVerLanguageNameW = DWORD(WINAPI*)(DWORD, LPWSTR, DWORD);
using FnVerQueryValueA = BOOL(WINAPI*)(LPCVOID, LPCSTR, LPVOID*, PUINT);
using FnVerQueryValueW = BOOL(WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

struct VersionExports {
    FnGetFileVersionInfoA GetFileVersionInfoA = nullptr;
    FnGetFileVersionInfoByHandle GetFileVersionInfoByHandle = nullptr;
    FnGetFileVersionInfoExA GetFileVersionInfoExA = nullptr;
    FnGetFileVersionInfoExW GetFileVersionInfoExW = nullptr;
    FnGetFileVersionInfoSizeA GetFileVersionInfoSizeA = nullptr;
    FnGetFileVersionInfoSizeExA GetFileVersionInfoSizeExA = nullptr;
    FnGetFileVersionInfoSizeExW GetFileVersionInfoSizeExW = nullptr;
    FnGetFileVersionInfoSizeW GetFileVersionInfoSizeW = nullptr;
    FnGetFileVersionInfoW GetFileVersionInfoW = nullptr;
    FnVerFindFileA VerFindFileA = nullptr;
    FnVerFindFileW VerFindFileW = nullptr;
    FnVerInstallFileA VerInstallFileA = nullptr;
    FnVerInstallFileW VerInstallFileW = nullptr;
    FnVerLanguageNameA VerLanguageNameA = nullptr;
    FnVerLanguageNameW VerLanguageNameW = nullptr;
    FnVerQueryValueA VerQueryValueA = nullptr;
    FnVerQueryValueW VerQueryValueW = nullptr;
} g_exports;

template <typename T>
void ResolveExport(T& target, const char* name) {
    target = reinterpret_cast<T>(GetProcAddress(g_real_version, name));
}

BOOL CALLBACK InitRealVersion(PINIT_ONCE /*init_once*/, PVOID /*param*/, PVOID* /*context*/) {
    wchar_t sys_dir[MAX_PATH]{};
    UINT len = GetSystemDirectoryW(sys_dir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH - 16) {
        return TRUE;
    }
    wcscat_s(sys_dir, L"\\version.dll");
    g_real_version = LoadLibraryW(sys_dir);
    if (!g_real_version) {
        return TRUE;
    }
    ResolveExport(g_exports.GetFileVersionInfoA, "GetFileVersionInfoA");
    ResolveExport(g_exports.GetFileVersionInfoByHandle, "GetFileVersionInfoByHandle");
    ResolveExport(g_exports.GetFileVersionInfoExA, "GetFileVersionInfoExA");
    ResolveExport(g_exports.GetFileVersionInfoExW, "GetFileVersionInfoExW");
    ResolveExport(g_exports.GetFileVersionInfoSizeA, "GetFileVersionInfoSizeA");
    ResolveExport(g_exports.GetFileVersionInfoSizeExA, "GetFileVersionInfoSizeExA");
    ResolveExport(g_exports.GetFileVersionInfoSizeExW, "GetFileVersionInfoSizeExW");
    ResolveExport(g_exports.GetFileVersionInfoSizeW, "GetFileVersionInfoSizeW");
    ResolveExport(g_exports.GetFileVersionInfoW, "GetFileVersionInfoW");
    ResolveExport(g_exports.VerFindFileA, "VerFindFileA");
    ResolveExport(g_exports.VerFindFileW, "VerFindFileW");
    ResolveExport(g_exports.VerInstallFileA, "VerInstallFileA");
    ResolveExport(g_exports.VerInstallFileW, "VerInstallFileW");
    ResolveExport(g_exports.VerLanguageNameA, "VerLanguageNameA");
    ResolveExport(g_exports.VerLanguageNameW, "VerLanguageNameW");
    ResolveExport(g_exports.VerQueryValueA, "VerQueryValueA");
    ResolveExport(g_exports.VerQueryValueW, "VerQueryValueW");
    return TRUE;
}

void EnsureLoaded() {
    InitOnceExecuteOnce(&g_init_once, InitRealVersion, nullptr, nullptr);
}

}  // namespace

extern "C" {

BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoA ? g_exports.GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

BOOL WINAPI Proxy_GetFileVersionInfoByHandle(DWORD dwFlags, HANDLE hFile, DWORD dwLen, LPVOID lpData) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoByHandle ? g_exports.GetFileVersionInfoByHandle(dwFlags, hFile, dwLen, lpData) : FALSE;
}

BOOL WINAPI Proxy_GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoExA ? g_exports.GetFileVersionInfoExA(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

BOOL WINAPI Proxy_GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoExW ? g_exports.GetFileVersionInfoExW(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoSizeA ? g_exports.GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoSizeExA ? g_exports.GetFileVersionInfoSizeExA(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoSizeExW ? g_exports.GetFileVersionInfoSizeExW(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoSizeW ? g_exports.GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle) : 0;
}

BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    EnsureLoaded();
    return g_exports.GetFileVersionInfoW ? g_exports.GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI Proxy_VerFindFileA(DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir, LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen) {
    EnsureLoaded();
    return g_exports.VerFindFileA ? g_exports.VerFindFileA(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen) : 0;
}

DWORD WINAPI Proxy_VerFindFileW(DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir, LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen) {
    EnsureLoaded();
    return g_exports.VerFindFileW ? g_exports.VerFindFileW(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen) : 0;
}

DWORD WINAPI Proxy_VerInstallFileA(DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir, LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT puTmpFileLen) {
    EnsureLoaded();
    return g_exports.VerInstallFileA ? g_exports.VerInstallFileA(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen) : 0;
}

DWORD WINAPI Proxy_VerInstallFileW(DWORD uFlags, LPCWSTR szSrcFileName, LPCWSTR szDestFileName, LPCWSTR szSrcDir, LPCWSTR szDestDir, LPCWSTR szCurDir, LPWSTR szTmpFile, PUINT puTmpFileLen) {
    EnsureLoaded();
    return g_exports.VerInstallFileW ? g_exports.VerInstallFileW(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen) : 0;
}

DWORD WINAPI Proxy_VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang) {
    EnsureLoaded();
    return g_exports.VerLanguageNameA ? g_exports.VerLanguageNameA(wLang, szLang, cchLang) : 0;
}

DWORD WINAPI Proxy_VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang) {
    EnsureLoaded();
    return g_exports.VerLanguageNameW ? g_exports.VerLanguageNameW(wLang, szLang, cchLang) : 0;
}

BOOL WINAPI Proxy_VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    EnsureLoaded();
    return g_exports.VerQueryValueA ? g_exports.VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}

BOOL WINAPI Proxy_VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    EnsureLoaded();
    return g_exports.VerQueryValueW ? g_exports.VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}

}  // extern "C"
