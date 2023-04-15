#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <tchar.h>
#include <vector>
#pragma comment( lib, "psapi" )
bool vk_n1Pressed = false;

using namespace std;

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
DWORD GetBaseAddress(const HANDLE hProcess);
uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets);
DWORD GetModuleBase(HANDLE hProc, string& sModuleName);

int main()
{
    DWORD pid = 0;
    HANDLE handle = NULL;
    DWORD processes[1024];
    DWORD needed;
    HANDLE hProcess = NULL;

    if (EnumProcesses(processes, sizeof(processes), &needed))
    {
        for (unsigned int i = 0; i < (needed / sizeof(DWORD)); i++)
        {
            if (processes[i] != 0)
            {
                TCHAR processName[MAX_PATH] = TEXT("<unknown>");

                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

                if (NULL != hProcess)
                {
                    HMODULE hMod;
                    DWORD cbNeeded;

                    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
                    {
                        GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(TCHAR));
                    }
                }
                CloseHandle(hProcess);

                if (_tcscmp(processName, TEXT("wesnoth.exe")) == 0)
                {
                    pid = processes[i];
                    handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                    break;
                }
            }
        }
    }

    if (pid == 0)
    {
        MessageBox(NULL, "Cannot find wesnoth.exe", "error", MB_OK + MB_ICONERROR);
        return 1;
    }
    else
    {
        HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
        MSG msg;

        while (true)
        {
            if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }

            if (vk_n1Pressed)
            {
                string moduleName = "wesnoth.exe";
                DWORD currentValue = 0;
                DWORD newValue = 0;
                DWORD increaseValue = 500;

                uintptr_t moduleBase = GetModuleBase(hProcess, moduleName);
                uintptr_t dynamicptrbaseaddr = moduleBase + 0x01150DB0;
                std::vector<unsigned int> offsets = { 0x4, 0x4 };
                uintptr_t FinalAddress = FindDMAAddy(hProcess, dynamicptrbaseaddr, offsets);

                ReadProcessMemory(handle, (PBYTE*)FinalAddress, (LPVOID)&currentValue, sizeof(currentValue), 0);
                newValue = currentValue + increaseValue;

                if (WriteProcessMemory(handle, (PBYTE*)FinalAddress, (LPCVOID)&newValue, sizeof(newValue), 0))
                    printf("%p -> %d\n", FinalAddress, newValue);  //MessageBox(NULL, "Wrote process memory !", "info", MB_OK + MB_ICONINFORMATION);
                else
                    MessageBox(NULL, "Cannot write process memory!", "error", MB_OK + MB_ICONERROR);

                vk_n1Pressed = false;
            }
        }
    }

    CloseHandle(handle);

    return 0;
}

DWORD GetBaseAddress(const HANDLE hProcess)
{
    if (hProcess == NULL)
        return NULL; // No access to the process

    HMODULE lphModule[1024]; // Array that receives the list of module handles
    DWORD lpcbNeeded(NULL); // Output of EnumProcessModules, giving the number of bytes requires to store all modules handles in the lphModule array

    if (!EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &lpcbNeeded))
        return NULL; // Impossible to read modules

    TCHAR szModName[MAX_PATH];
    if (!GetModuleFileNameEx(hProcess, lphModule[0], szModName, sizeof(szModName) / sizeof(TCHAR)))
        return NULL; // Impossible to get module info

    return (DWORD)lphModule[0]; // Module 0 is apparently always the EXE itself, returning its address
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;

    if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
        if (p->vkCode == 97 || p->vkCode == 35)
            vk_n1Pressed = true;
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets)
{
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
        addr += offsets[i];
    }
    return addr;
}

DWORD GetModuleBase(HANDLE hProc, string& sModuleName)
{
    HMODULE* hModules = nullptr;
    char szBuf[50];
    DWORD cModules;
    DWORD dwBase = -1;
    //------ 
    EnumProcessModules(hProc, hModules, 0, &cModules);
    hModules = new HMODULE[cModules / sizeof(HMODULE)];
    if (EnumProcessModules(hProc, hModules, cModules / sizeof(HMODULE), &cModules)) {
        for (int i = 0; i < cModules / sizeof(HMODULE); i++) {
            if (GetModuleBaseName(hProc, hModules[i], szBuf, sizeof(szBuf))) {
                if (sModuleName.compare(szBuf) == 0) {
                    dwBase = (DWORD)hModules[i];
                    break;
                }
            }
        }
    }
    delete[] hModules;
    return dwBase;
}