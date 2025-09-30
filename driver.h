#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <vector>
#include <iostream>
#include <algorithm>
#include <string>
#include <sstream>
#include <cstring>
#include <Psapi.h>
#include <cctype>       // para std::isspace, std::isxdigit
#include <iomanip>      // para std::setw e std::setfill

#include <cctype>

extern uintptr_t virtualaddy;

extern uintptr_t codeCaveBase;

#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1645, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1646, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_get_guarded_region CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1647, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_security 0x85b3b69
#define IOCTL_ALLOCATE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Memory allocation request structure for the driver
typedef struct _ALLOCATE_MEMORY_REQUEST {
    ULONGLONG BaseAddress;       // Base address for allocation
    ULONGLONG Size;              // Size of memory to allocate
    ULONGLONG AllocatedAddress;  // Address of allocated memory (output)
} ALLOCATE_MEMORY_REQUEST, * PALLOCATE_MEMORY_REQUEST;


namespace mem {
    extern HANDLE driver_handle;
    extern INT32 process_id;

    bool find_driver();
    void read_physical(PVOID address, PVOID buffer, DWORD size);
    bool write_physical(PVOID address, PVOID buffer, DWORD size);
    uintptr_t find_image();
    uintptr_t get_guarded_region();
    INT32 find_process(LPCTSTR process_name);
    uintptr_t get_module_base(DWORD processID, const char* moduleName);
    uintptr_t allocate_memory_with_driver(uintptr_t baseAddress, size_t size);
    bool ExecuteInjectionViaDriver(DWORD pid, uintptr_t dllPathAddress);
    bool UnloadDriver(HANDLE hDriver);


}


inline bool write_buffer(uint64_t address, const void* buffer, size_t size) {
    try {
        mem::write_physical(reinterpret_cast<PVOID>(address), const_cast<void*>(buffer), size);
        return true; // Escrita bem-sucedida
    }
    catch (...) {
        return false; // Falha na escrita
    }
}
// AOB scanning function accessible globally

inline std::vector<uintptr_t> AOBScan(uintptr_t startAddress, uintptr_t endAddress, const std::vector<std::string>& pattern) {
    constexpr size_t chunkSize = 0x1000;
    std::vector<BYTE> buffer(chunkSize);
    std::vector<uintptr_t> results;

    std::vector<BYTE> bytePattern;
    std::vector<bool> isWildcard;

    for (const auto& token : pattern) {
        if (token == "?") {
            bytePattern.push_back(0);
            isWildcard.push_back(true);
        }
        else {
            bytePattern.push_back(static_cast<BYTE>(std::stoul(token, nullptr, 16)));
            isWildcard.push_back(false);
        }
    }

    for (uintptr_t address = startAddress; address < endAddress; address += chunkSize) {
        size_t bytesToRead = chunkSize;
        if (address + chunkSize > endAddress) {
            bytesToRead = endAddress - address;
        }

        mem::read_physical(reinterpret_cast<PVOID>(address), buffer.data(), bytesToRead);

        for (size_t i = 0; i <= bytesToRead - bytePattern.size(); ++i) {
            bool match = true;

            for (size_t j = 0; j < bytePattern.size(); ++j) {
                if (!isWildcard[j] && buffer[i + j] != bytePattern[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                results.push_back(address + i);
            }
        }
    }

    return results;
}



inline std::vector<BYTE> createJumpBack(uintptr_t fromAddress, uintptr_t toAddress, size_t instructionLength) {
    uintptr_t relativeOffset = toAddress - (fromAddress + instructionLength);
    return {
        0xE9, // JMP opcode
        static_cast<BYTE>(relativeOffset & 0xFF),
        static_cast<BYTE>((relativeOffset >> 8) & 0xFF),
        static_cast<BYTE>((relativeOffset >> 16) & 0xFF),
        static_cast<BYTE>((relativeOffset >> 24) & 0xFF),
    };
}



// Template functions for memory read/write
template <typename T>
T read(uint64_t address) {
    T buffer{ };
    mem::read_physical((PVOID)address, &buffer, sizeof(T));
    return buffer;
}

template <typename T>
bool write(uint64_t address, T buffer) {

    return mem::write_physical((PVOID)address, &buffer, sizeof(T));
}

// Constants

inline std::vector<uintptr_t> AOBScan(
    uintptr_t startAddress,
    uintptr_t endAddress,
    const std::string& patternStr   // aceita literal como voc� quer
) {
    // 1) Parse da string de padr�o em bytes + wildcards
    std::vector<BYTE>      bytePattern;
    std::vector<bool>      isWildcard;
    std::istringstream     iss(patternStr);
    std::string            token;
    while (iss >> token) {
        if (token == "?" || token == "??") {
            bytePattern.push_back(0x00);
            isWildcard.push_back(true);
        }
        else {
            bytePattern.push_back(static_cast<BYTE>(std::stoul(token, nullptr, 16)));
            isWildcard.push_back(false);
        }
    }

    // 2) Varre em blocos de 0x1000 bytes
    constexpr size_t chunkSize = 0x1000;
    std::vector<BYTE> buffer(chunkSize);
    std::vector<uintptr_t> results;

    for (uintptr_t addr = startAddress; addr < endAddress; addr += chunkSize) {
        size_t bytesToRead = chunkSize;
        if (addr + chunkSize > endAddress)
            bytesToRead = endAddress - addr;

        mem::read_physical(reinterpret_cast<PVOID>(addr), buffer.data(), bytesToRead);

        // 3) Checa cada offset dentro do chunk
        for (size_t i = 0; i + bytePattern.size() <= bytesToRead; ++i) {
            bool match = true;
            for (size_t j = 0; j < bytePattern.size(); ++j) {
                if (!isWildcard[j] && buffer[i + j] != bytePattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                results.push_back(addr + i);
            }
        }
    }

    return results;
}