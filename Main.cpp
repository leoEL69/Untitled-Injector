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

#define ID_PROCESS_LIST 1001
#define ID_INJECT_BUTTON 1002
#define ID_DLL_BROWSE_EDIT 1004
#define ID_BROWSE_BUTTON 1005
#define ID_METHOD_COMBO 1006
#define ID_SEARCH_EDIT 1008
#define ID_SEARCH_BUTTON 1009
#define ID_CLEAR_BUTTON 1010
#define CONTEXT_TOGGLE_PAUSE 2006

enum ProcessStatus {
    Running,
    Paused,
    Terminated
};
#define CONTEXT_PAUSE_PROCESS 2006
#define ID_MODULES_WND   3001
#define ID_MODULES_LIST  3002
#define ID_MODULES_CLOSE 3003


LRESULT CALLBACK WndProcModules(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);



#define CONTEXT_OPEN_LOCATION 2001
#define CONTEXT_SHOW_MODULES  2002
#define CONTEXT_SHOW_PE       2003
#define CONTEXT_SHOW_WINDOW   2004
#define CONTEXT_TERMINATE_PROCESS 2005

enum InjectionMethod {
    METHOD_LOADLIBRARY = 0,
    METHOD_MANUALMAP,
    METHOD_THREADHIJACK,
    METHOD_APC,
    METHOD_SETWINDOWSHOOK,
    METHOD_REFLECTIVE,
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


HWND hMainWnd, hProcessList, hInjectBtn, hDllPathEdit, hBrowseBtn, hMethodCombo;
HWND hSearchEdit, hSearchBtn, hClearBtn, hGuideText;

std::vector<ProcessInfo> g_processes;
std::vector<ProcessInfo> g_filteredProcesses;
HIMAGELIST g_hImageList = NULL;

HFONT g_hFont = NULL;
HBRUSH g_hBrushBackground = CreateSolidBrush(RGB(255, 255, 255));
HBRUSH g_hBrushControl = CreateSolidBrush(RGB(255, 255, 255));
COLORREF g_crText = RGB(0, 0, 0);


void RefreshProcessList();
void SearchProcesses(const std::wstring& query);
void CreateUIControls(HWND hWnd);
void ResizeUI(HWND hWnd);
DWORD GetSelectedProcessPID();
void BrowseDLLFile();
bool PerformInjection(DWORD pid, const wchar_t* dllPath, InjectionMethod method);
void ShowContextMenu(HWND hwnd, POINT pt);



bool ManualMapInject(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }

    BYTE* pLocalDll = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalDll) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, pLocalDll, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(pLocalDll, 0, MEM_RELEASE);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pLocalDll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pLocalDll + pDosHeader->e_lfanew);

    BYTE* pRemoteDll = (BYTE*)VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteDll) {
        VirtualFree(pLocalDll, 0, MEM_RELEASE);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }

  
    WriteProcessMemory(hProcess, pRemoteDll, pLocalDll, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);


    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++) {
        if (pSection->SizeOfRawData) {
            WriteProcessMemory(hProcess, pRemoteDll + pSection->VirtualAddress,
                pLocalDll + pSection->PointerToRawData, pSection->SizeOfRawData, NULL);
        }
    }


    LPTHREAD_START_ROUTINE pEntryPoint = (LPTHREAD_START_ROUTINE)(pRemoteDll + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pEntryPoint, pRemoteDll, 0, NULL);

    bool success = false;
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        success = true;
    }

    VirtualFree(pLocalDll, 0, MEM_RELEASE);
    CloseHandle(hFile);
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

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD targetThreadId = 0;

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

    // Allocate memory for DLL path
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemoteMem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);

    // Hijack thread execution
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    SuspendThread(hThread);
    GetThreadContext(hThread, &ctx);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    // Save original RIP and set new one
    DWORD_PTR originalRip = ctx.Rip;
    ctx.Rip = (DWORD_PTR)pLoadLibrary;

    // Set RCX to point to DLL path
    ctx.Rcx = (DWORD_PTR)pRemoteMem;

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    // Wait for injection to complete
    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// APC Injection Implementation
bool APCInject(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    // Allocate memory for DLL path
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pRemoteMem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    // Find threads in the target process
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

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

bool SetWindowsHookInject(DWORD pid, const wchar_t* dllPath) {
 
    HMODULE hDll = LoadLibraryW(dllPath);
    if (!hDll) return false;


    HOOKPROC pHookProc = (HOOKPROC)GetProcAddress(hDll, "HookProc");
    if (!pHookProc) {
        FreeLibrary(hDll);
        return false;
    }

   
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        FreeLibrary(hDll);
        return false;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD targetThreadId = 0;

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
        FreeLibrary(hDll);
        return false;
    }

   
    g_hHook = SetWindowsHookEx(WH_GETMESSAGE, pHookProc, hDll, targetThreadId);
    if (!g_hHook) {
        FreeLibrary(hDll);
        return false;
    }


    PostThreadMessage(targetThreadId, WM_NULL, 0, 0);
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
    if (!pDllData) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }

    DWORD bytesRead;
    ReadFile(hFile, pDllData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllData;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pDllData + pDosHeader->e_lfanew);


    BYTE* pRemoteDll = (BYTE*)VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<wchar_t*>(info.name.c_str());
        lvi.iImage = iconIndex;
        int idx = ListView_InsertItem(hProcessList, &lvi);
        ListView_SetItemText(hProcessList, idx, 1, const_cast<wchar_t*>(info.pidStr.c_str()));
        ListView_SetItemText(hProcessList, idx, 2, const_cast<wchar_t*>(info.fullPath.c_str()));
    }
}

void RefreshProcessList() {
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
    case METHOD_LOADLIBRARY:
        return InjectLoadLibrary(pid, dllPath);
    case METHOD_MANUALMAP:
        return ManualMapInject(pid, dllPath);
    case METHOD_THREADHIJACK:
        return ThreadHijackInject(pid, dllPath);
    case METHOD_APC:
        return APCInject(pid, dllPath);
    case METHOD_SETWINDOWSHOOK:
        return SetWindowsHookInject(pid, dllPath);
    case METHOD_REFLECTIVE:
        return ReflectiveInject(pid, dllPath);
    default:
        return false;
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
    if (MessageBoxW(hMainWnd, L"Are you sure you want to pause this process?", L"Confirm Pause",
        MB_YESNO | MB_ICONQUESTION) != IDYES)
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


void ShowModules(DWORD pid) {
    // Criar janela pai para o ListView
    HWND hModuleWnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEW,
        L"Modules",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 400,
        hMainWnd, NULL, GetModuleHandle(NULL), NULL
    );

    // Inicializar Common Controls
    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icex);

    wchar_t col1[] = L"Module Name";
    wchar_t col2[] = L"Base Addr";
    wchar_t col3[] = L"Size";
    wchar_t col4[] = L"Path";

    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.cx = 150; lvc.pszText = col1; ListView_InsertColumn(hModuleWnd, 0, &lvc);
    lvc.cx = 80;  lvc.pszText = col2; ListView_InsertColumn(hModuleWnd, 1, &lvc);
    lvc.cx = 80;  lvc.pszText = col3; ListView_InsertColumn(hModuleWnd, 2, &lvc);
    lvc.cx = 350; lvc.pszText = col4; ListView_InsertColumn(hModuleWnd, 3, &lvc);

    // Snapshot dos módulos
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int index = 0;

    if (Module32FirstW(hSnapshot, &me)) {
        do {
            // Inserir item
            LVITEMW item = { 0 };
            item.mask = LVIF_TEXT;
            item.iItem = index;
            item.iSubItem = 0;
            item.pszText = me.szModule;
            ListView_InsertItem(hModuleWnd, &item);

            // Base Address
            wchar_t buffer[32];
            swprintf(buffer, 32, L"0x%p", me.modBaseAddr);
            ListView_SetItemText(hModuleWnd, index, 1, buffer);

            // Size
            swprintf(buffer, 32, L"%zu bytes", me.modBaseSize);
            ListView_SetItemText(hModuleWnd, index, 2, buffer);

            // Path
            ListView_SetItemText(hModuleWnd, index, 3, me.szExePath);

            ++index;
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
}


void ShowPE(DWORD pid) {
    auto it = std::find_if(g_filteredProcesses.begin(), g_filteredProcesses.end(),
        [pid](const ProcessInfo& p) { return p.pid == pid; });

    if (it == g_filteredProcesses.end() || it->fullPath == L"N/A") {
        MessageBoxW(hMainWnd, L"Unable to access process file", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    HANDLE hFile = CreateFileW(it->fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        MessageBoxW(hMainWnd, L"Failed to open executable file", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMapping) {
        CloseHandle(hFile);
        MessageBoxW(hMainWnd, L"Failed to create file mapping", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    LPVOID pBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        MessageBoxW(hMainWnd, L"Failed to map view of file", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    std::wstring peInfo;
    peInfo += L"PE Header Information:\n\n";
    peInfo += L"Machine: 0x" + std::to_wstring(pNtHeaders->FileHeader.Machine) + L"\n";
    peInfo += L"Number of Sections: " + std::to_wstring(pNtHeaders->FileHeader.NumberOfSections) + L"\n";
    peInfo += L"Entry Point: 0x" + std::to_wstring(pNtHeaders->OptionalHeader.AddressOfEntryPoint) + L"\n";
    peInfo += L"Image Base: 0x" + std::to_wstring((DWORD_PTR)pNtHeaders->OptionalHeader.ImageBase) + L"\n";
    peInfo += L"Size of Image: " + std::to_wstring(pNtHeaders->OptionalHeader.SizeOfImage) + L" bytes\n";

    UnmapViewOfFile(pBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    MessageBoxW(hMainWnd, peInfo.c_str(), L"PE Information", MB_OK | MB_ICONINFORMATION);
}

void ShowWindowType(DWORD pid) {
    std::wstring windowInfo;
    HWND hWnd = NULL;

    // Find windows belonging to this process
    while ((hWnd = FindWindowEx(NULL, hWnd, NULL, NULL)) != NULL) {
        DWORD windowPid;
        GetWindowThreadProcessId(hWnd, &windowPid);

        if (windowPid == pid) {
            wchar_t title[256];
            GetWindowTextW(hWnd, title, 256);

            windowInfo += L"Window Handle: 0x" + std::to_wstring((DWORD_PTR)hWnd) + L"\n";
            windowInfo += L"Title: " + std::wstring(title) + L"\n";
            windowInfo += L"Class: ";

            wchar_t className[256];
            GetClassNameW(hWnd, className, 256);
            windowInfo += std::wstring(className) + L"\n";

            RECT rect;
            if (GetWindowRect(hWnd, &rect)) {
                windowInfo += L"Position: (" + std::to_wstring(rect.left) + L"," + std::to_wstring(rect.top) +
                    L") Size: " + std::to_wstring(rect.right - rect.left) + L"x" +
                    std::to_wstring(rect.bottom - rect.top) + L"\n";
            }

            windowInfo += L"Visible: " + std::wstring(IsWindowVisible(hWnd) ? L"Yes" : L"No") + L"\n";
            windowInfo += L"Enabled: " + std::wstring(IsWindowEnabled(hWnd) ? L"Yes" : L"No") + L"\n\n";
        }
    }

    if (windowInfo.empty()) {
        windowInfo = L"No visible windows found for this process.";
    }

    MessageBoxW(hMainWnd, windowInfo.c_str(), L"Window Information", MB_OK | MB_ICONINFORMATION);
}

void TerminateProcess(DWORD pid) {
    if (MessageBoxW(hMainWnd, L"Are you sure you want to terminate this process?", L"Confirm Termination",
        MB_YESNO | MB_ICONWARNING) == IDYES) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            if (TerminateProcess(hProcess, 0)) {
                MessageBoxW(hMainWnd, L"Process terminated successfully", L"Success", MB_OK | MB_ICONINFORMATION);
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
    AppendMenuW(hMenu, MF_STRING, CONTEXT_SHOW_WINDOW, L"Show Window Info");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, CONTEXT_TERMINATE_PROCESS, L"💀 Terminate Process");

    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    if (cmd == CONTEXT_OPEN_LOCATION) OpenFileLocation(pid);
    else if (cmd == CONTEXT_SHOW_MODULES) ShowModules(pid);
    else if (cmd == CONTEXT_SHOW_PE) ShowPE(pid);
    else if (cmd == CONTEXT_SHOW_WINDOW) ShowWindowType(pid);
    else if (cmd == CONTEXT_TERMINATE_PROCESS) TerminateProcess(pid);


    DestroyMenu(hMenu);
}


LRESULT CALLBACK WndProcModules(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
  
        LPCREATESTRUCT lpcs = (LPCREATESTRUCT)lParam;
        auto* pMods = (std::vector<MODULEENTRY32W>*)lpcs->lpCreateParams;
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)pMods);

     
        HWND hList = CreateWindowExW(0, WC_LISTVIEW, NULL,
            WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
            10, 10, 660, 360, hWnd, (HMENU)ID_MODULES_LIST, GetModuleHandle(NULL), NULL);


        ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP | LVS_EX_DOUBLEBUFFER);


        LVCOLUMNW col = { 0 };
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 180; col.pszText = (LPWSTR)L"Module"; ListView_InsertColumn(hList, 0, &col);
        col.cx = 300; col.pszText = (LPWSTR)L"Path";   ListView_InsertColumn(hList, 1, &col);
        col.cx = 100; col.pszText = (LPWSTR)L"Base";   ListView_InsertColumn(hList, 2, &col);
        col.cx = 80;  col.pszText = (LPWSTR)L"Size";   ListView_InsertColumn(hList, 3, &col);

        // botão fechar
        CreateWindowW(L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            580, 380, 90, 28, hWnd, (HMENU)ID_MODULES_CLOSE, GetModuleHandle(NULL), NULL);

     
        if (pMods && !pMods->empty()) {
            int index = 0;
            for (const auto& m : *pMods) {
                LVITEMW item = { 0 };
                item.mask = LVIF_TEXT;
                item.iItem = index;
                item.pszText = const_cast<LPWSTR>(m.szModule);
                ListView_InsertItem(hList, &item);

                wchar_t buf[64];
                // imprime endereço base e tamanho
                wsprintfW(buf, L"0x%p", (void*)m.modBaseAddr);
                ListView_SetItemText(hList, index, 2, buf);

                wchar_t sizeBuf[64];
                wsprintfW(sizeBuf, L"%u", m.modBaseSize);
                ListView_SetItemText(hList, index, 3, sizeBuf);

                // path
                ListView_SetItemText(hList, index, 1, const_cast<LPWSTR>(m.szExePath));

                index++;
            }
        }
        else {
            LVITEMW item = { 0 };
            item.mask = LVIF_TEXT;
            item.iItem = 0;
            item.pszText = (LPWSTR)L"No modules found or access denied.";
            ListView_InsertItem(hList, &item);
        }

        break;
    }

    case WM_SIZE: {
        RECT rc; GetClientRect(hWnd, &rc);
        HWND hList = GetDlgItem(hWnd, ID_MODULES_LIST);
        if (hList) {
            int btnHeight = 50;
            MoveWindow(hList, 10, 10, rc.right - 20, rc.bottom - 20 - btnHeight, TRUE);
        }
        HWND hBtn = GetDlgItem(hWnd, ID_MODULES_CLOSE);
        if (hBtn) {
            MoveWindow(hBtn, rc.right - 100, rc.bottom - 40, 90, 28, TRUE);
        }
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_MODULES_CLOSE) {
            DestroyWindow(hWnd);
        }
        break;

    case WM_DESTROY: {
        // libera vector alocado em ShowModules
        auto* pMods = (std::vector<MODULEENTRY32W>*)GetWindowLongPtrW(hWnd, GWLP_USERDATA);
        if (pMods) {
            delete pMods;
            SetWindowLongPtrW(hWnd, GWLP_USERDATA, 0);
        }
        break;
    }

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
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

  
            std::wstring confirmMsg = L"Target PID: " + std::to_wstring(pid) + L"\n";
            confirmMsg += L"DLL: " + std::wstring(dllPath) + L"\n";
            confirmMsg += L"Method: " + std::to_wstring(method) + L"\n\nConfirm injection?";

            if (MessageBoxW(hWnd, confirmMsg.c_str(), L"Confirm Injection", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                bool ok = PerformInjection(pid, dllPath, method);
                MessageBoxW(hWnd, ok ? L"✅ Injection Successful!" : L"❌ Injection Failed.",
                    L"Nightfury Injector", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
            }
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
        if (nmhdr->idFrom == ID_PROCESS_LIST && nmhdr->code == NM_DBLCLK) {
      
            DWORD pid = GetSelectedProcessPID();
            if (pid) {
                wchar_t dllPath[MAX_PATH];
                GetWindowTextW(hDllPathEdit, dllPath, MAX_PATH);
                if (wcslen(dllPath)) {
                    InjectionMethod method = (InjectionMethod)SendMessage(hMethodCombo, CB_GETCURSEL, 0, 0);
                    PerformInjection(pid, dllPath, method);
                }
            }
        }
        break;
    }

    case WM_CONTEXTMENU: {
        if ((HWND)wParam == hProcessList) {
            POINT pt;
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
            ShowContextMenu(hWnd, pt);
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, g_crText);
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, g_crText);
        SetBkColor(hdc, RGB(255, 255, 255));
        return (LRESULT)g_hBrushControl;
    }

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
    g_hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        VARIABLE_PITCH | FF_SWISS, L"Segoe UI Variable");

    hSearchEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, (HMENU)ID_SEARCH_EDIT, NULL, NULL);
    hSearchBtn = CreateWindowW(L"BUTTON", L"🔍 Search", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_SEARCH_BUTTON, NULL, NULL);
    hClearBtn = CreateWindowW(L"BUTTON", L"🗑️ Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_CLEAR_BUTTON, NULL, NULL);

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
        L"1. LoadLibrary (Standard)",
        L"2. Manual Mapping (Advanced)",
        L"3. Thread Hijacking (Stealth)",
        L"4. APC Injection (Async)",
        L"5. SetWindowsHook (GUI)",
        L"6. Reflective DLL (Ultra Stealth)"
    };
    for (int i = 0; i < METHOD_TOTAL; i++) SendMessageW(hMethodCombo, CB_ADDSTRING, 0, (LPARAM)methods[i]);
    SendMessageW(hMethodCombo, CB_SETCURSEL, 0, 0);

    hGuideText = CreateWindowW(L"STATIC", L"💉 Untitled DLL Inj - Select process and DLL, then click Inject",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, hWnd, NULL, NULL, NULL);
    hDllPathEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 0, 0, hWnd, (HMENU)ID_DLL_BROWSE_EDIT, NULL, NULL);
    hBrowseBtn = CreateWindowW(L"BUTTON", L"📂 Browse DLL", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_BROWSE_BUTTON, NULL, NULL);
    hInjectBtn = CreateWindowW(L"BUTTON", L"🚀 INJECT DLL", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)ID_INJECT_BUTTON, NULL, NULL);

    HWND controls[] = { hSearchEdit,hSearchBtn,hClearBtn,hProcessList,hMethodCombo,hGuideText,hDllPathEdit,hBrowseBtn,hInjectBtn };
    for (HWND c : controls) SendMessage(c, WM_SETFONT, (WPARAM)g_hFont, TRUE);
}

void ResizeUI(HWND hWnd) {
    RECT rc; GetClientRect(hWnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    const int M = 10, H = 25, BW = 80;

    int searchEditW = w - 4 * M - BW * 2;
    SetWindowPos(hSearchEdit, NULL, 2 * M, 2 * M, searchEditW, H, SWP_NOZORDER);
    SetWindowPos(hSearchBtn, NULL, 3 * M + searchEditW, 2 * M, BW, H, SWP_NOZORDER);
    SetWindowPos(hClearBtn, NULL, 4 * M + searchEditW + BW, 2 * M, BW, H, SWP_NOZORDER);

    int listY = 2 * M + H + M, listH = h - listY - 100;
    SetWindowPos(hProcessList, NULL, M, listY, w - 2 * M, listH, SWP_NOZORDER);

    int bottomControlsY = h - M - (H * 2) - 10;
    int comboW = 250;
    SetWindowPos(hMethodCombo, NULL, M, bottomControlsY, comboW, H, SWP_NOZORDER);

    int injectW = 120, browseW = 100, dllW = w - 4 * M - injectW - browseW;
    SetWindowPos(hDllPathEdit, NULL, M, bottomControlsY + H + 10, dllW, H, SWP_NOZORDER);
    SetWindowPos(hBrowseBtn, NULL, 2 * M + dllW, bottomControlsY + H + 10, browseW, H, SWP_NOZORDER);
    SetWindowPos(hInjectBtn, NULL, 3 * M + dllW + browseW, bottomControlsY + H + 10, injectW, H, SWP_NOZORDER);
}

std::wstring RandomString(size_t length) {
    const std::wstring chars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::wstring result;
    result.reserve(length);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, (int)chars.size() - 1);

    for (size_t i = 0; i < length; ++i)
        result += chars[dis(gen)];

    return result;
}


void RandomizeWindowTitle(HWND hwnd) {
    while (true) {
        std::wstring newTitle = RandomString(30); 
        SetWindowTextW(hwnd, newTitle.c_str());
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); 
    }
}


int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    InitCommonControls();
   

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"Untitled";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    hMainWnd = CreateWindowW(L"Untitled", L"Untitled DLL Injct",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 700, NULL, NULL, hInst, NULL);

    ShowWindow(hMainWnd, nCmdShow);
    UpdateWindow(hMainWnd);

    // Inicia a thread que muda o título
    std::thread(RandomizeWindowTitle, hMainWnd).detach();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}