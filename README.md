# Untitled-Injector

A simple DLL injector written in C++ with a graphical interface for Windows. This project also includes basic process management features, allowing you to select a running process and inject a DLL into it.

---

## Features

- List running processes on the system.
- Select a target process for DLL injection.
- DLL injection using WinAPI (`OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
- Simple GUI for easier interaction.
- Display process status (running, paused, etc.) in the UI.
- Support for pausing and resuming processes directly from the context menu.

---

## Requirements

- Windows 10/11 (x64 recommended)
- Visual Studio 2019 or higher
- Windows SDK
- Standard Windows libraries (WinAPI)

---

## How to Compile

1. Clone the repository:
   ```bash
   git clone https://github.com/leoEL69/Untitled-Injector.git


   <img width="926" height="748" alt="image" src="https://github.com/user-attachments/assets/55d21c9d-8cb0-4101-b7c1-b59ff4ea0f76" />

