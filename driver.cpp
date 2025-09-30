#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <vector>
#include <sstream>
#include <string>
#include <cstdlib>
#include "driver.h"
#include <iostream>
#include <algorithm>
#include <Psapi.h>

uintptr_t virtualaddy;
uintptr_t codeCaveBase;


#define IOCTL_UNLOAD_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_EXECUTE_INJECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1645, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1646, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_guarded_region CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1647, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_security 0x85b3b69
#define IOCTL_ALLOCATE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _rw {
	INT32 security;
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
} rw, * prw;

typedef struct _ba {
	INT32 security;
	INT32 process_id;
	ULONGLONG* address;
} ba, * pba;

typedef struct _ga {
	INT32 security;
	ULONGLONG* address;
} ga, * pga;


typedef struct _KERNEL_INJECT_EXECUTE {
	INT32 security;
	INT32 process_id;
	ULONGLONG dll_path_address;
	ULONGLONG loadlibrary_addr;
} KERNEL_INJECT_EXECUTE, * PKERNEL_INJECT_EXECUTE;





namespace mem {
	HANDLE driver_handle;
	INT32 process_id;

	bool find_driver() {
		driver_handle = CreateFileW((L"\\\\.\\\{4CF37457-D723-A910-F4AC-56E93D9C2D17}"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (!driver_handle || (driver_handle == INVALID_HANDLE_VALUE))
			return false;

		return true;
	}

	void read_physical(PVOID address, PVOID buffer, DWORD size) {
		_rw arguments = { 0 };

		arguments.security = code_security;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = process_id;
		arguments.write = FALSE;

		DeviceIoControl(driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	bool write_physical(PVOID address, PVOID buffer, DWORD size) {
		_rw arguments = { 0 };

		arguments.security = code_security;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = process_id;
		arguments.write = TRUE;

		// 1. Chame DeviceIoControl e guarde o resultado.
		BOOL success = DeviceIoControl(
			driver_handle,
			code_rw,
			&arguments,
			sizeof(arguments),
			nullptr,
			0,
			nullptr,
			nullptr
		);

		// 2. Retorne 'true' se 'success' for diferente de zero, e 'false' caso contr�rio.
		return success != 0;
	}

	uintptr_t find_image() {
		uintptr_t image_address = { NULL };
		_ba arguments = { NULL };

		arguments.security = code_security;
		arguments.process_id = process_id;
		arguments.address = (ULONGLONG*)&image_address;

		DeviceIoControl(driver_handle, code_ba, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}

	uintptr_t get_guarded_region() {
		uintptr_t guarded_region_address = { NULL };
		_ga arguments = { NULL };

		arguments.security = code_security;
		arguments.address = (ULONGLONG*)&guarded_region_address;

		DeviceIoControl(driver_handle, code_get_guarded_region, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return guarded_region_address;
	}

	INT32 find_process(LPCTSTR process_name) {
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name)) {
					CloseHandle(hsnap);
					process_id = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);

		return { NULL };
	}


	bool ExecuteInjectionViaDriver(DWORD pid, uintptr_t dllPathAddress) {
		typedef struct _KERNEL_INJECT_EXECUTE {
			INT32 security;
			INT32 process_id;
			ULONGLONG dll_path_address;
			ULONGLONG loadlibrary_addr;
		} KERNEL_INJECT_EXECUTE;

		KERNEL_INJECT_EXECUTE inject_cmd = { 0 };
		inject_cmd.security = code_security;
		inject_cmd.process_id = pid;
		inject_cmd.dll_path_address = dllPathAddress;

		// CRITICAL FIX: Kernel must resolve LoadLibraryW in target process
		inject_cmd.loadlibrary_addr = 0; // Let kernel handle this

		DWORD bytes_returned;
		BOOL success = DeviceIoControl(
			mem::driver_handle,
			IOCTL_EXECUTE_INJECTION,
			&inject_cmd,
			sizeof(inject_cmd),
			NULL,
			0,
			&bytes_returned,
			NULL
		);

		return success;
	}



	bool UnloadDriver(HANDLE hDriver) {
		if (!hDriver || hDriver == INVALID_HANDLE_VALUE)
			return false;

		DWORD bytes = 0;
		BOOL result = DeviceIoControl(
			hDriver,
			IOCTL_UNLOAD_DRIVER,
			nullptr,
			0,
			nullptr,
			0,
			&bytes,
			nullptr
		);

		if (!result) {
			std::cerr << "Failed to send unload request. Error: " << GetLastError() << "\n";
			return false;
		}

		CloseHandle(hDriver);
		return true;


	}

	uintptr_t allocate_memory_with_driver(uintptr_t baseAddress, size_t size) {
		ALLOCATE_MEMORY_REQUEST request = { baseAddress, size, 0 };

		DWORD bytesReturned;
		BOOL success = DeviceIoControl(
			driver_handle,
			IOCTL_ALLOCATE_MEMORY,
			&request,
			sizeof(request),
			&request,
			sizeof(request),
			&bytesReturned,
			nullptr
		);

		if (!success || request.AllocatedAddress == 0) {
			std::cerr << "[-] Failed to allocate memory. Error: " << GetLastError() << "\n";
			return 0;
		}

		std::cout << "[+] Allocated memory at: 0x" << std::hex << request.AllocatedAddress << "\n";
		return request.AllocatedAddress;
	}
}
