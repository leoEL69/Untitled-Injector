#include <windows.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <algorithm>
#include <windowsx.h>
#include <iostream>
#include <psapi.h>
#include <dbghelp.h>
#include <thread>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include "driver.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

#pragma comment(linker,"/manifestdependency:\"type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// IDs dos Controles
#define ID_PROCESS_LIST 1001
#define ID_INJECT_BUTTON 1002
#define ID_DLL_BROWSE_EDIT 1004
#define ID_BROWSE_BUTTON 1005
#define ID_METHOD_COMBO 1006
#define ID_SEARCH_EDIT 1008
#define ID_SEARCH_BUTTON 1009
#define ID_CLEAR_BUTTON 1010
#define ID_SETTINGS_BUTTON 1011
#define ID_REFRESH_TIMER 1012 

// IDs do Menu de Contexto
#define CONTEXT_OPEN_LOCATION 2001
#define CONTEXT_SHOW_MODULES  2002
#define CONTEXT_SHOW_PE       2003
#define CONTEXT_SHOW_WINDOW   2004
#define CONTEXT_TERMINATE_PROCESS 2005
#define CONTEXT_TOGGLE_PAUSE 2006
#define CONTEXT_PAUSE_PROCESS 2006
#define CONTEXT_DUMP_MODULE   2007
#define CONTEXT_TOGGLE_SUSPEND 2008
#define CONTEXT_DUMP_PROCESS 2010 

// IDs da Janela de Módulos e Configurações
#define ID_MODULES_WND   3001
#define ID_MODULES_LIST  3002
#define ID_MODULES_CLOSE 3003
#define ID_SETTINGS_UNLOAD_DRIVER 4001


// Protótipos
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WndProcModules(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam); 
LRESULT CALLBACK WndProcSettings(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void ShowSettingsWindow();
void UnloadDriver();
void CreateUIControls(HWND hWnd);
void ResizeUI(HWND hWnd);
void SearchProcesses(const std::wstring& query);
void DumpModule(DWORD pid, const MODULEENTRY32W& moduleInfo);


enum InjectionMethod {
    METHOD_LOADLIBRARY = 0,
    METHOD_MANUALMAP,
    METHOD_THREADHIJACK,
    METHOD_APC,
    METHOD_SETWINDOWSHOOK,
    METHOD_REFLECTIVE,
    METHOD_KERNEL_DRIVER,
    METHOD_TOTAL
};

struct ProcessInfo {
    DWORD pid;
    std::wstring name;
    std::wstring fullPath;
    HICON icon;
    std::wstring pidStr;
    HANDLE hProcess;
};

// --- Globais ---
HWND hMainWnd, hProcessList, hInjectBtn, hDllPathEdit, hBrowseBtn, hMethodCombo;
HWND hSearchEdit, hSearchBtn, hClearBtn, hGuideText, hSettingsBtn;
HWND hSettingsWnd = NULL; 

std::vector<ProcessInfo> g_processes;
std::vector<ProcessInfo> g_filteredProcesses;
HIMAGELIST g_hImageList = NULL;

HFONT g_hFont = NULL;
HBRUSH g_hBrushBackground = CreateSolidBrush(RGB(255, 255, 255));
HBRUSH g_hBrushControl = CreateSolidBrush(RGB(255, 255, 255));
COLORREF g_crText = RGB(0, 0, 0);


void initiatedriver() {
    if (mem::find_driver()) {
        MessageBoxW(NULL, L"Driver opened successfully.", L"Success", MB_ICONINFORMATION);
    }
    else {
        MessageBoxW(NULL, L"Failed to open driver. Make sure the driver is installed and you have the necessary permissions.", L"Error", MB_ICONERROR);
    }
}


bool ManualMapInject(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* pLocalDll = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalDll) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }

    DWORD bytesRead;
    ReadFile(hFile, pLocalDll, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pLocalDll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pLocalDll + pDosHeader->e_lfanew);

    BYTE* pRemoteDll = (BYTE*)VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteDll) {
        VirtualFree(pLocalDll, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemoteDll, pLocalDll, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++) {
        if (pSection->SizeOfRawData) {
            WriteProcessMemory(hProcess, pRemoteDll + pSection->VirtualAddress, pLocalDll + pSection->PointerToRawData, pSection->SizeOfRawData, NULL);
        }
    }

    LPTHREAD_START_ROUTINE pEntryPoint = (LPTHREAD_START_ROUTINE)(pRemoteDll + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pEntryPoint, pRemoteDll, 0, NULL);

    bool success = hThread != NULL;
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFree(pLocalDll, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return success;
}

bool ThreadHijackInject(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }

    DWORD targetThreadId = 0;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                targetThreadId = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    if (!targetThreadId) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);
    if (!hThread) {
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemoteMem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    SuspendThread(hThread);
    GetThreadContext(hThread, &ctx);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    ctx.Rip = (DWORD_PTR)pLoadLibrary;
    ctx.Rcx = (DWORD_PTR)pRemoteMem;
    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

bool APCInject(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return false;
    }
    WriteProcessMemory(hProcess, pRemoteMem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    bool injected = false;
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)pRemoteMem);
                    CloseHandle(hThread);
                    injected = true;
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return injected;
}

HHOOK g_hHook = NULL;
bool SetWindowsHookInject(DWORD pid, const wchar_t* dllPath) {
    DWORD tid = 0;
    HWND currentHwnd = NULL;
    while ((currentHwnd = FindWindowEx(NULL, currentHwnd, NULL, NULL)) != NULL) {
        DWORD windowPid;
        DWORD windowTid = GetWindowThreadProcessId(currentHwnd, &windowPid);
        if (windowPid == pid) {
            tid = windowTid;
            break;
        }
    }
    if (tid == 0) return false;

    HMODULE dll = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (dll == NULL) return false;

    HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "NextHook");
    if (addr == NULL) {
        addr = (HOOKPROC)GetProcAddress(dll, "HookProc");
    }
    if (addr == NULL) {
        FreeLibrary(dll);
        return false;
    }
    g_hHook = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, tid);
    if (g_hHook == NULL) {
        FreeLibrary(dll);
        return false;
    }
    PostThreadMessage(tid, WM_NULL, NULL, NULL);
    return true;
}

bool ReflectiveInject(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* pDllData = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ReadFile(hFile, pDllData, fileSize, NULL, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pDllData + pDosHeader->e_lfanew);

    BYTE* pRemoteDll = (BYTE*)VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteDll) {
        VirtualFree(pDllData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemoteDll, pDllData, pNtHeaders->OptionalHeader.SizeOfImage, NULL);

    DWORD_PTR loaderOffset = 0x1000; 
    LPTHREAD_START_ROUTINE pReflectiveLoader = (LPTHREAD_START_ROUTINE)(pRemoteDll + loaderOffset);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pReflectiveLoader, pRemoteDll, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteDll, 0, MEM_RELEASE);
        VirtualFree(pDllData, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(pDllData, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}

bool KernelDriverInject(DWORD pid, const wchar_t* dllPath) {
    if (!dllPath || !mem::find_driver()) {
        MessageBoxW(NULL, L"Driver not available", L"Error", MB_ICONERROR);
        return false;
    }
    mem::process_id = pid;
    SIZE_T dll_path_size = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    uintptr_t remote_memory = mem::allocate_memory_with_driver(0, dll_path_size);

    if (!remote_memory) {
        MessageBoxW(NULL, L"Failed to allocate memory via driver", L"Error", MB_ICONERROR);
        return false;
    }
    if (!mem::write_physical((PVOID)remote_memory, (PVOID)dllPath, dll_path_size)) {
        MessageBoxW(NULL, L"Failed to write DLL path via driver", L"Error", MB_ICONERROR);
        return false;
    }
    return mem::ExecuteInjectionViaDriver(pid, remote_memory);
}



void ToggleSuspendProcess(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        MessageBoxW(NULL, L"Failed to get thread snapshot.", L"Error", MB_ICONERROR);
        return;
    }

   
    bool shouldResume = false;
    bool actionDetermined = false;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThreadCheck = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThreadCheck) {
                  
           
                    DWORD suspendCount = SuspendThread(hThreadCheck);
                    if (suspendCount != (DWORD)-1) {
               
                        ResumeThread(hThreadCheck);
                        if (suspendCount > 0) {
                            shouldResume = true;
                        }
                    }
                    CloseHandle(hThreadCheck);
                    actionDetermined = true;
                    break; 
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    if (!actionDetermined) {
        MessageBoxW(NULL, L"Could not determine process state or find any threads.", L"Warning", MB_ICONWARNING);
        CloseHandle(hSnapshot);
        return;
    }

  
    if (Thread32First(hSnapshot, &te)) { 
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (shouldResume) {
                        ResumeThread(hThread);
                    }
                    else {
                        SuspendThread(hThread);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);

    if (shouldResume) {
        MessageBoxW(NULL, L"Process resumed successfully.", L"Success", MB_ICONINFORMATION);
    }
    else {
        MessageBoxW(NULL, L"Process suspended successfully.", L"Success", MB_ICONINFORMATION);
    }
}




BOOL SetDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result;
}

std::wstring GetProcessPath(DWORD pid) {
    wchar_t path[MAX_PATH] = { 0 };
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            CloseHandle(hProcess);
            return path;
        }
        CloseHandle(hProcess);
    }
    return L"N/A";
}

HICON GetProcessIcon(const std::wstring& path) {
    if (path.empty() || path == L"N/A") return NULL;
    SHFILEINFOW sfi = { 0 };
    if (SHGetFileInfoW(path.c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON)) {
        return sfi.hIcon;
    }
    return NULL;
}

void PopulateProcessList(const std::vector<ProcessInfo>& procs) {
    if (!g_hImageList) {
        g_hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 1);
        ListView_SetImageList(hProcessList, g_hImageList, LVSIL_SMALL);
    }
    else {
        ImageList_RemoveAll(g_hImageList);
    }
    ListView_DeleteAllItems(hProcessList);
    HICON defaultIcon = LoadIcon(NULL, IDI_APPLICATION);
    int defaultIconIndex = ImageList_AddIcon(g_hImageList, defaultIcon);
    DestroyIcon(defaultIcon);

    for (size_t i = 0; i < procs.size(); ++i) {
        const auto& info = procs[i];
        int iconIndex = defaultIconIndex;
        if (info.icon) {
            HICON copyIcon = (HICON)CopyImage(info.icon, IMAGE_ICON, 16, 16, LR_COPYFROMRESOURCE);
            if (copyIcon) {
                iconIndex = ImageList_AddIcon(g_hImageList, copyIcon);
                DestroyIcon(copyIcon);
            }
        }
        LVITEMW lvi = { 0 };
        lvi.mask = LVIF_TEXT | LVIF_IMAGE;
        lvi.iItem = i;
        lvi.pszText = const_cast<wchar_t*>(info.name.c_str());
        lvi.iImage = iconIndex;
        int idx = ListView_InsertItem(hProcessList, &lvi);
        ListView_SetItemText(hProcessList, idx, 1, const_cast<wchar_t*>(info.pidStr.c_str()));
        ListView_SetItemText(hProcessList, idx, 2, const_cast<wchar_t*>(info.fullPath.c_str()));
    }
}

void RefreshProcessList() {
    
    for (const auto& proc : g_processes) {
        if (proc.icon) DestroyIcon(proc.icon);
        if (proc.hProcess) CloseHandle(proc.hProcess);
    }
    g_processes.clear();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.pidStr = std::to_wstring(info.pid);
            info.name = pe.szExeFile;
            info.fullPath = GetProcessPath(pe.th32ProcessID);
            info.icon = GetProcessIcon(info.fullPath);
            info.hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, info.pid);
            g_processes.push_back(info);
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    SearchProcesses(L"");
}

void SearchProcesses(const std::wstring& query) {
    g_filteredProcesses.clear();
    if (query.empty()) {
        g_filteredProcesses = g_processes;
    }
    else {
        std::wstring queryLower = query;
        std::transform(queryLower.begin(), queryLower.end(), queryLower.begin(), ::towlower);
        for (const auto& proc : g_processes) {
            std::wstring nameLower = proc.name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);
            if (nameLower.find(queryLower) != std::wstring::npos || proc.pidStr.find(query) != std::wstring::npos) {
                g_filteredProcesses.push_back(proc);
            }
        }
    }
    PopulateProcessList(g_filteredProcesses);
}


void DumpMainModule(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        MessageBoxW(NULL, L"Failed to create module snapshot to find the main executable.", L"Dump Error", MB_ICONERROR);
        return;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

  
    if (Module32FirstW(hSnap, &me)) {
     
        DumpModule(pid, me);
    }
    else {
        MessageBoxW(NULL, L"Failed to find the main module for the selected process.", L"Dump Error", MB_ICONERROR);
    }

    CloseHandle(hSnap);
}


DWORD GetSelectedProcessPID() {
    int idx = ListView_GetNextItem(hProcessList, -1, LVNI_SELECTED);
    if (idx != -1 && idx < g_filteredProcesses.size()) {
        return g_filteredProcesses[idx].pid;
    }
    return 0;
}

void BrowseDLLFile() {
    OPENFILENAMEW ofn = { 0 };
    wchar_t fileName[MAX_PATH] = L"";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWnd;
    ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (GetOpenFileNameW(&ofn)) {
        SetWindowTextW(hDllPathEdit, fileName);
    }
}

bool InjectLoadLibrary(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;
    bool success = false;
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteMem) {
        if (WriteProcessMemory(hProcess, pRemoteMem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL)) {
            HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
            LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteMem, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, INFINITE);
                DWORD exitCode = 0;
                GetExitCodeThread(hThread, &exitCode);
                if (exitCode != 0) success = true;
                CloseHandle(hThread);
            }
        }
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    }
    CloseHandle(hProcess);
    return success;
}

bool PerformInjection(DWORD pid, const wchar_t* dllPath, InjectionMethod method) {
    switch (method) {
    case METHOD_LOADLIBRARY: return InjectLoadLibrary(pid, dllPath);
    case METHOD_MANUALMAP: return ManualMapInject(pid, dllPath);
    case METHOD_THREADHIJACK: return ThreadHijackInject(pid, dllPath);
    case METHOD_APC: return APCInject(pid, dllPath);
    case METHOD_SETWINDOWSHOOK: return SetWindowsHookInject(pid, dllPath);
    case METHOD_REFLECTIVE: return ReflectiveInject(pid, dllPath);
    case METHOD_KERNEL_DRIVER: return KernelDriverInject(pid, dllPath);
    default: return false;
    }
}


void OpenFileLocation(DWORD pid) {
    auto it = std::find_if(g_filteredProcesses.begin(), g_filteredProcesses.end(),
        [pid](const ProcessInfo& p) { return p.pid == pid; });
    if (it != g_filteredProcesses.end() && it->fullPath != L"N/A") {
        std::wstring command = L"/select,\"" + it->fullPath + L"\"";
        ShellExecuteW(NULL, L"open", L"explorer.exe", command.c_str(), NULL, SW_SHOWNORMAL);
    }
}

void PauseProcess(DWORD pid) {
    if (MessageBoxW(hMainWnd, L"Are you sure you want to pause this process?", L"Confirm Pause", MB_YESNO | MB_ICONQUESTION) != IDYES)
        return;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    MessageBoxW(hMainWnd, L"Process paused successfully.", L"Success", MB_OK | MB_ICONINFORMATION);
}


void DumpModule(DWORD pid, const MODULEENTRY32W& moduleInfo) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        MessageBoxW(NULL, L"Failed to open target process for reading.", L"Dump Error", MB_ICONERROR);
        return;
    }

    BYTE* rawMemoryDump = new (std::nothrow) BYTE[moduleInfo.modBaseSize];
    if (!rawMemoryDump) {
        MessageBoxW(NULL, L"Failed to allocate memory for the raw dump.", L"Dump Error", MB_ICONERROR);
        CloseHandle(hProcess);
        return;
    }

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, moduleInfo.modBaseAddr, rawMemoryDump, moduleInfo.modBaseSize, &bytesRead) || bytesRead != moduleInfo.modBaseSize) {
        MessageBoxW(NULL, L"Failed to read module from process memory.", L"Dump Error", MB_ICONERROR);
        delete[] rawMemoryDump;
        CloseHandle(hProcess);
        return;
    }
    CloseHandle(hProcess);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)rawMemoryDump;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        MessageBoxW(NULL, L"Invalid DOS signature. Cannot rebuild PE.", L"Rebuild Error", MB_ICONERROR);
        delete[] rawMemoryDump;
        return;
    }
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(rawMemoryDump + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        MessageBoxW(NULL, L"Invalid NT signature. Cannot rebuild PE.", L"Rebuild Error", MB_ICONERROR);
        delete[] rawMemoryDump;
        return;
    }

    DWORD finalFileSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        finalFileSize += section->SizeOfRawData;
    }

    BYTE* rebuiltFileBuffer = new (std::nothrow) BYTE[finalFileSize];
    if (!rebuiltFileBuffer) {
        MessageBoxW(NULL, L"Failed to allocate memory for the rebuilt PE.", L"Rebuild Error", MB_ICONERROR);
        delete[] rawMemoryDump;
        return;
    }
    memset(rebuiltFileBuffer, 0, finalFileSize);

    memcpy_s(rebuiltFileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, rawMemoryDump, ntHeaders->OptionalHeader.SizeOfHeaders);

    section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->VirtualAddress > 0 && section->PointerToRawData > 0 && section->SizeOfRawData > 0) {
            if ((section->VirtualAddress + section->SizeOfRawData <= moduleInfo.modBaseSize) &&
                (section->PointerToRawData + section->SizeOfRawData <= finalFileSize))
            {
                memcpy_s(
                    rebuiltFileBuffer + section->PointerToRawData,
                    section->SizeOfRawData,
                    rawMemoryDump + section->VirtualAddress,
                    section->SizeOfRawData
                );
            }
        }
    }

    // --- THIS IS THE UPGRADED PART ---
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    std::wstring moduleNameStr(moduleInfo.szModule);
    size_t lastDot = moduleNameStr.find_last_of(L'.');
    std::wstring baseName = (lastDot == std::wstring::npos) ? moduleNameStr : moduleNameStr.substr(0, lastDot);
    std::wstring extension = (lastDot == std::wstring::npos) ? L"" : moduleNameStr.substr(lastDot); // Grab the original extension
    std::wstring newFileName = baseName + L"_Dump" + extension; // And slap it on the end
    std::wstring dumpFileName = std::wstring(exePath) + L"\\" + newFileName;
    // --- END OF UPGRADE ---

    HANDLE hFile = CreateFileW(dumpFileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        MessageBoxW(NULL, L"Failed to create dump file on disk.", L"Dump Error", MB_ICONERROR);
        delete[] rawMemoryDump;
        delete[] rebuiltFileBuffer;
        return;
    }

    DWORD bytesWritten = 0;
    WriteFile(hFile, rebuiltFileBuffer, finalFileSize, &bytesWritten, NULL);
    CloseHandle(hFile);

    delete[] rawMemoryDump;
    delete[] rebuiltFileBuffer;

    std::wstring successMsg = L"Successfully REBUILT module to:\n" + dumpFileName;
    MessageBoxW(NULL, successMsg.c_str(), L"✅ Rebuild Successful!", MB_ICONINFORMATION);
}



void ShowModules(DWORD pid) {
    
    wchar_t existingTitle[256];
    swprintf(existingTitle, 256, L"Modules (PID: %d)", pid);
    HWND hExistingWnd = FindWindowW(L"UntitledModules", existingTitle);
    if (hExistingWnd) {
        SetForegroundWindow(hExistingWnd);
        return;
    }

    wchar_t title[256];
    swprintf(title, 256, L"Modules (PID: %d)", pid);

    HWND hModuleWnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"UntitledModules", 
        title,
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 500,
        hMainWnd,
        NULL,
        GetModuleHandle(NULL),
        (LPVOID)pid 
    );

    if (hModuleWnd) {
        ShowWindow(hModuleWnd, SW_SHOW);
    }
}
void ShowPE(DWORD pid) {
    auto it = std::find_if(g_filteredProcesses.begin(), g_filteredProcesses.end(), [pid](const ProcessInfo& p) { return p.pid == pid; });
    if (it == g_filteredProcesses.end() || it->fullPath == L"N/A") {
        MessageBoxW(hMainWnd, L"Unable to access process file", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    HANDLE hFile = CreateFileW(it->fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMapping) { CloseHandle(hFile); return; }
    LPVOID pBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) { CloseHandle(hFileMapping); CloseHandle(hFile); return; }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    std::wstringstream ss;
    ss << L"PE Header Information:\n\n"
        << L"Machine: 0x" << std::hex << pNtHeaders->FileHeader.Machine << L"\n"
        << L"Number of Sections: " << std::dec << pNtHeaders->FileHeader.NumberOfSections << L"\n"
        << L"Entry Point: 0x" << std::hex << pNtHeaders->OptionalHeader.AddressOfEntryPoint << L"\n"
        << L"Image Base: 0x" << pNtHeaders->OptionalHeader.ImageBase << L"\n"
        << L"Size of Image: " << std::dec << pNtHeaders->OptionalHeader.SizeOfImage << L" bytes\n";
    MessageBoxW(hMainWnd, ss.str().c_str(), L"PE Information", MB_OK | MB_ICONINFORMATION);

    UnmapViewOfFile(pBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}

void ShowWindowType(DWORD pid) {
    std::wstringstream ss;
    HWND hWnd = NULL;
    bool found = false;
    while ((hWnd = FindWindowEx(NULL, hWnd, NULL, NULL)) != NULL) {
        DWORD windowPid;
        GetWindowThreadProcessId(hWnd, &windowPid);
        if (windowPid == pid) {
            found = true;
            wchar_t title[256], className[256];
            GetWindowTextW(hWnd, title, 256);
            GetClassNameW(hWnd, className, 256);
            RECT rect;
            GetWindowRect(hWnd, &rect);

            ss << L"Window Handle: 0x" << std::hex << (DWORD_PTR)hWnd << L"\n"
                << L"Title: " << title << L"\n"
                << L"Class: " << className << L"\n"
                << L"Position: (" << std::dec << rect.left << L"," << rect.top << L") Size: "
                << (rect.right - rect.left) << L"x" << (rect.bottom - rect.top) << L"\n"
                << L"Visible: " << (IsWindowVisible(hWnd) ? L"Yes" : L"No") << L"\n\n";
        }
    }
    std::wstring info = found ? ss.str() : L"No visible windows found for this process.";
    MessageBoxW(hMainWnd, info.c_str(), L"Window Information", MB_OK | MB_ICONINFORMATION);
}

void TerminateProcess(DWORD pid) {
    if (MessageBoxW(hMainWnd, L"Are you sure you want to terminate this process?", L"Confirm Termination", MB_YESNO | MB_ICONWARNING) == IDYES) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            if (::TerminateProcess(hProcess, 0)) {
                MessageBoxW(hMainWnd, L"Process terminated successfully", L"Success", MB_OK);
                RefreshProcessList();
            }
            else {
                MessageBoxW(hMainWnd, L"Failed to terminate process", L"Error", MB_OK | MB_ICONERROR);
            }
            CloseHandle(hProcess);
        }
        else {
            MessageBoxW(hMainWnd, L"Unable to open process for termination", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void ShowContextMenu(HWND hwnd, POINT pt) {
    DWORD pid = GetSelectedProcessPID();
    if (!pid) return;

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, CONTEXT_OPEN_LOCATION, L"📁 Open File Location");
    AppendMenuW(hMenu, MF_STRING, CONTEXT_SHOW_MODULES, L"🔧 Show Modules");
    AppendMenuW(hMenu, MF_STRING, CONTEXT_SHOW_PE, L"📊 Show PE Info");
    AppendMenuW(hMenu, MF_STRING, CONTEXT_SHOW_WINDOW, L"🖼️ Show Window Info");

    AppendMenuW(hMenu, MF_STRING, CONTEXT_DUMP_PROCESS, L"🚀 Dump Process");


    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, CONTEXT_TOGGLE_SUSPEND, L"⏯️ Suspend/Resume Process");
    AppendMenuW(hMenu, MF_STRING, CONTEXT_TERMINATE_PROCESS, L"💀 Terminate Process");

    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);

    switch (cmd) {
    case CONTEXT_OPEN_LOCATION: OpenFileLocation(pid); break;
    case CONTEXT_SHOW_MODULES: ShowModules(pid); break;
    case CONTEXT_SHOW_PE: ShowPE(pid); break;
    case CONTEXT_SHOW_WINDOW: ShowWindowType(pid); break;
    case CONTEXT_DUMP_PROCESS: DumpMainModule(pid); break; 
    case CONTEXT_TOGGLE_SUSPEND: ToggleSuspendProcess(pid); break;
    case CONTEXT_TERMINATE_PROCESS: TerminateProcess(pid); break;
    }
}



LRESULT CALLBACK WndProcModules(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hModuleList = NULL;
    static DWORD currentPid = 0;

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        currentPid = (DWORD)(pCreate->lpCreateParams);

        hModuleList = CreateWindowExW(0, WC_LISTVIEW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            0, 0, 800, 500, hWnd, (HMENU)ID_MODULES_LIST, GetModuleHandle(NULL), NULL);

        ListView_SetExtendedListViewStyle(hModuleList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        const wchar_t* columns[] = { L"Module Name", L"Base Addr", L"Size", L"Path" };
        int widths[] = { 180, 120, 100, 350 };
        LVCOLUMNW lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (int i = 0; i < 4; ++i) {
            lvc.cx = widths[i];
            lvc.pszText = (LPWSTR)columns[i];
            ListView_InsertColumn(hModuleList, i, &lvc);
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, currentPid);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me;
            me.dwSize = sizeof(me);
            if (Module32FirstW(hSnapshot, &me)) {
                int index = 0;
                do {
                    MODULEENTRY32W* pMe = new MODULEENTRY32W(me);
                    LVITEMW item = { 0 };
                    item.mask = LVIF_TEXT | LVIF_PARAM;
                    item.iItem = index;
                    item.pszText = me.szModule;
                    item.lParam = (LPARAM)pMe; 
                    ListView_InsertItem(hModuleList, &item);

                    wchar_t buffer[64];
                    swprintf(buffer, 64, L"0x%p", me.modBaseAddr);
                    ListView_SetItemText(hModuleList, index, 1, buffer);
                    swprintf(buffer, 64, L"%zu bytes", me.modBaseSize);
                    ListView_SetItemText(hModuleList, index, 2, buffer);
                    ListView_SetItemText(hModuleList, index, 3, me.szExePath);
                    index++;
                } while (Module32NextW(hSnapshot, &me));
            }
            CloseHandle(hSnapshot);
        }
        break;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hWnd, &rc);
        SetWindowPos(hModuleList, NULL, 0, 0, rc.right, rc.bottom, SWP_NOZORDER);
        break;
    }

    case WM_NOTIFY: {
        LPNMHDR nmhdr = (LPNMHDR)lParam;
        if (nmhdr->idFrom == ID_MODULES_LIST && nmhdr->code == NM_RCLICK) {
            int selectedItem = ListView_GetNextItem(hModuleList, -1, LVNI_SELECTED);
            if (selectedItem != -1) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, CONTEXT_DUMP_MODULE, L"🚀 Dump Module");
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
                DestroyMenu(hMenu);
            }
        }
        break;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == CONTEXT_DUMP_MODULE) {
            int selectedItem = ListView_GetNextItem(hModuleList, -1, LVNI_SELECTED);
            if (selectedItem != -1) {
                LVITEMW item = { 0 };
                item.mask = LVIF_PARAM;
                item.iItem = selectedItem;
                if (ListView_GetItem(hModuleList, &item)) {
                    MODULEENTRY32W* pMe = (MODULEENTRY32W*)item.lParam;
                    DumpModule(currentPid, *pMe);
                }
            }
        }
        break;
    }

    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;

    case WM_DESTROY: {
    
        int count = ListView_GetItemCount(hModuleList);
        for (int i = 0; i < count; i++) {
            LVITEMW item = { 0 };
            item.mask = LVIF_PARAM;
            item.iItem = i;
            if (ListView_GetItem(hModuleList, &item)) {
                delete (MODULEENTRY32W*)item.lParam;
            }
        }
        break;
    }

    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}



LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateUIControls(hWnd);
        RefreshProcessList();
        break;

    case WM_SIZE:
        ResizeUI(hWnd);
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BROWSE_BUTTON: BrowseDLLFile(); break;
        case ID_SETTINGS_BUTTON: ShowSettingsWindow(); break;
        case ID_SEARCH_BUTTON: {
            wchar_t buf[256]; GetWindowTextW(hSearchEdit, buf, 256);
            SearchProcesses(buf); break;
        }
        case ID_CLEAR_BUTTON:
            SetWindowTextW(hSearchEdit, L"");
            RefreshProcessList();
            SetFocus(hSearchEdit);
            break;
        case ID_INJECT_BUTTON: {
            DWORD pid = GetSelectedProcessPID();
            if (!pid) { MessageBoxW(hWnd, L"Select a process.", L"Error", MB_OK | MB_ICONERROR); break; }
            wchar_t dllPath[MAX_PATH]; GetWindowTextW(hDllPathEdit, dllPath, MAX_PATH);
            if (!wcslen(dllPath)) { MessageBoxW(hWnd, L"Select a DLL.", L"Error", MB_OK | MB_ICONERROR); break; }

            InjectionMethod method = (InjectionMethod)SendMessage(hMethodCombo, CB_GETCURSEL, 0, 0);
            bool ok = PerformInjection(pid, dllPath, method);
            MessageBoxW(hWnd, ok ? L"✅ Injection Successful!" : L"❌ Injection Failed.", L"Untitled Injector", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
            break;
        }
        default:
            if (LOWORD(wParam) == ID_SEARCH_EDIT && HIWORD(wParam) == EN_CHANGE) {
                wchar_t buf[256]; GetWindowTextW(hSearchEdit, buf, 256);
                SearchProcesses(buf);
            }
            break;
        }
        break;

    case WM_NOTIFY: {
        LPNMHDR nmhdr = (LPNMHDR)lParam;
        if (nmhdr->idFrom == ID_PROCESS_LIST && nmhdr->code == NM_RCLICK) {
            POINT pt;
            GetCursorPos(&pt);
            ShowContextMenu(hWnd, pt);
        }
        break;
    }

    case WM_CONTEXTMENU:
        if ((HWND)wParam == hProcessList) {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.x == -1 && pt.y == -1) { 
                RECT rc;
                GetWindowRect(hProcessList, &rc);
                pt.x = rc.left + 5;
                pt.y = rc.top + 5;
            }
            ShowContextMenu(hWnd, pt);
        }
        break;

    case WM_CTLCOLORSTATIC: return (LRESULT)GetStockObject(WHITE_BRUSH);
    case WM_CTLCOLOREDIT: return (LRESULT)g_hBrushControl;

    case WM_DESTROY:
        if (g_hImageList) ImageList_Destroy(g_hImageList);
        DeleteObject(g_hFont);
        DeleteObject(g_hBrushBackground);
        DeleteObject(g_hBrushControl);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}


void CreateUIControls(HWND hWnd) {
    g_hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, L"Segoe UI Variable");

    hSearchEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, (HMENU)ID_SEARCH_EDIT, NULL, NULL);
    hSearchBtn = CreateWindowW(L"BUTTON", L"🔍 Search", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_SEARCH_BUTTON, NULL, NULL);
    hClearBtn = CreateWindowW(L"BUTTON", L"🗑️ Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_CLEAR_BUTTON, NULL, NULL);
    hSettingsBtn = CreateWindowW(L"BUTTON", L"⚙️ Settings", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_SETTINGS_BUTTON, NULL, NULL);

    hProcessList = CreateWindowW(WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL, 0, 0, 0, 0, hWnd, (HMENU)ID_PROCESS_LIST, NULL, NULL);
    ListView_SetExtendedListViewStyle(hProcessList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP | LVS_EX_DOUBLEBUFFER);
    ListView_SetBkColor(hProcessList, RGB(255, 255, 255));
    ListView_SetTextColor(hProcessList, RGB(0, 0, 0));

    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    lvc.cx = 220; lvc.pszText = (LPWSTR)L"📄 Process Name"; ListView_InsertColumn(hProcessList, 0, &lvc);
    lvc.cx = 80; lvc.pszText = (LPWSTR)L"🔢 PID"; ListView_InsertColumn(hProcessList, 1, &lvc);
    lvc.cx = 400; lvc.pszText = (LPWSTR)L"📁 Path"; ListView_InsertColumn(hProcessList, 2, &lvc);

    hMethodCombo = CreateWindowW(WC_COMBOBOX, L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 0, 0, 0, 0, hWnd, (HMENU)ID_METHOD_COMBO, NULL, NULL);
    const wchar_t* methods[] = {
        L"1. LoadLibrary (Standard)", L"2. Manual Mapping (Advanced)",
        L"3. Thread Hijacking (Stealth)", L"4. APC Injection (Async)",
        L"5. SetWindowsHook (GUI)", L"6. Reflective DLL (Ultra Stealth)",
        L"7. Kernel Driver (Maximum Privilege)"
    };
    for (int i = 0; i < METHOD_TOTAL; i++) SendMessageW(hMethodCombo, CB_ADDSTRING, 0, (LPARAM)methods[i]);
    SendMessageW(hMethodCombo, CB_SETCURSEL, 0, 0);

    hDllPathEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 0, 0, hWnd, (HMENU)ID_DLL_BROWSE_EDIT, NULL, NULL);
    hBrowseBtn = CreateWindowW(L"BUTTON", L"📂 Browse DLL", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_BROWSE_BUTTON, NULL, NULL);
    hInjectBtn = CreateWindowW(L"BUTTON", L"🚀 INJECT DLL", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_INJECT_BUTTON, NULL, NULL);

    HWND controls[] = { hSearchEdit, hSearchBtn, hClearBtn, hSettingsBtn, hProcessList, hMethodCombo, hGuideText, hDllPathEdit, hBrowseBtn, hInjectBtn };
    for (HWND c : controls) if (c) SendMessage(c, WM_SETFONT, (WPARAM)g_hFont, TRUE);
}

void ResizeUI(HWND hWnd) {
    RECT rc; GetClientRect(hWnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    const int M = 10, H = 25, BW = 90; 

    // Linha superior de controles
    int settingsW = BW;
    int clearW = BW;
    int searchW = BW;
    int searchEditW = w - 5 * M - settingsW - clearW - searchW;
    SetWindowPos(hSearchEdit, NULL, M, M, searchEditW, H, SWP_NOZORDER);
    SetWindowPos(hSearchBtn, NULL, M + searchEditW + M, M, searchW, H, SWP_NOZORDER);
    SetWindowPos(hClearBtn, NULL, M + searchEditW + M + searchW + M, M, clearW, H, SWP_NOZORDER);
    SetWindowPos(hSettingsBtn, NULL, w - M - settingsW, M, settingsW, H, SWP_NOZORDER);

    // Lista de processos
    int listY = M + H + M, listH = h - listY - 100;
    SetWindowPos(hProcessList, NULL, M, listY, w - 2 * M, listH, SWP_NOZORDER);

    // Controles inferiores de injeção
    int bottomControlsY = h - M - (H * 2) - 10;
    int comboW = 250;
    SetWindowPos(hMethodCombo, NULL, M, bottomControlsY, comboW, H, SWP_NOZORDER);

    int injectW = 120, browseW = 120, dllW = w - 4 * M - injectW - browseW;
    SetWindowPos(hDllPathEdit, NULL, M, bottomControlsY + H + 10, dllW, H, SWP_NOZORDER);
    SetWindowPos(hBrowseBtn, NULL, M + dllW + M, bottomControlsY + H + 10, browseW, H, SWP_NOZORDER);
    SetWindowPos(hInjectBtn, NULL, M + dllW + M + browseW + M, bottomControlsY + H + 10, injectW, H, SWP_NOZORDER);
}


void ShowSettingsWindow() {
    if (hSettingsWnd && IsWindow(hSettingsWnd)) {
        SetForegroundWindow(hSettingsWnd);
        return;
    }
    hSettingsWnd = CreateWindowW(L"UntitledSettings", L"Settings",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 200, hMainWnd, NULL, GetModuleHandle(NULL), NULL);

    if (hSettingsWnd) {
        ShowWindow(hSettingsWnd, SW_SHOW);
    }
}

void UnloadDriver() {
    if (mem::driver_handle && mem::driver_handle != INVALID_HANDLE_VALUE) {
    mem::UnloadDriver(mem::driver_handle);
        mem::driver_handle = INVALID_HANDLE_VALUE;
        MessageBoxW(hSettingsWnd, L"Driver handle has been closed.", L"Driver Unload", MB_ICONINFORMATION);
    }
    else {
        MessageBoxW(hSettingsWnd, L"Driver is not currently loaded or handle is invalid.", L"Driver Unload", MB_ICONWARNING);
    }
}

LRESULT CALLBACK WndProcSettings(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HWND hBtnUnload = CreateWindowW(L"BUTTON", L"Unload Driver",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            50, 50, 180, 40,
            hWnd, (HMENU)ID_SETTINGS_UNLOAD_DRIVER, GetModuleHandle(NULL), NULL);
        SendMessage(hBtnUnload, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_SETTINGS_UNLOAD_DRIVER) {
            UnloadDriver();
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;
    case WM_DESTROY:
        hSettingsWnd = NULL; 
        break;
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

std::wstring RandomString(size_t length) {
    const std::wstring chars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::wstring result;
    result.reserve(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, (int)chars.size() - 1);
    for (size_t i = 0; i < length; ++i) result += chars[dis(gen)];
    return result;
}

void RandomizeWindowTitle(HWND hwnd) {
    while (true) {
        std::wstring newTitle = RandomString(100);
        SetWindowTextW(hwnd, newTitle.c_str());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// --- Ponto de Entrada ---
// --- Ponto de Entrada ---
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    InitCommonControls();
    initiatedriver();


    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"UntitledInjector";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

 
    WNDCLASSW wcModules = { 0 };
    wcModules.lpfnWndProc = WndProcModules;
    wcModules.hInstance = hInst;
    wcModules.lpszClassName = L"UntitledModules";
    wcModules.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcModules.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wcModules);
  

    WNDCLASSW wcSettings = { 0 };
    wcSettings.lpfnWndProc = WndProcSettings;
    wcSettings.hInstance = hInst;
    wcSettings.lpszClassName = L"UntitledSettings";
    wcSettings.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcSettings.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wcSettings);


    hMainWnd = CreateWindowW(L"UntitledInjector", L"Untitled DLL Inject",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 950, 700, NULL, NULL, hInst, NULL);

    ShowWindow(hMainWnd, nCmdShow);
    UpdateWindow(hMainWnd);

    std::thread(RandomizeWindowTitle, hMainWnd).detach();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}