#include<stdio.h>
#include<windows.h>
#include<TlHelp32.h>
#include<vector>
#include<winternl.h>
#include<DbgHelp.h>

using std::vector;

typedef NTSTATUS(WINAPI* fnNtQueryInformationThread) (
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength

);

fnNtQueryInformationThread NtQueryInformationThread1 = (fnNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread");

DWORD GetProcessIdFromName(const char* targetProcessName) {

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    while (Process32Next(snapshot, &pe32)) {
        if (!strcmp(pe32.szExeFile, targetProcessName)) {
            CloseHandle(snapshot);
            return pe32.th32ProcessID;
        }
    }

    CloseHandle(snapshot);
    return -1;
}


vector<HANDLE> GetProcessThreads(DWORD processId) {
    vector<HANDLE> threads;
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    while (Thread32Next(snapshot, &te32)) {
        if (te32.th32OwnerProcessID == processId) {
            threads.push_back(
                OpenThread(
                    THREAD_ALL_ACCESS,
                    FALSE,
                    te32.th32ThreadID
                )
            );
        }
        
    }

    CloseHandle(snapshot);
    return threads;

}

const char* GetThreadStartAddressSymbol(HANDLE process, DWORD64 threadStartAddress) {
    PVOID symbolBuffer = malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);

    RtlZeroMemory(symbolBuffer, sizeof(symbolBuffer));

    PSYMBOL_INFO symbolInfo = (PSYMBOL_INFO)symbolBuffer;
    symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo->MaxNameLen = MAX_SYM_NAME;

    SymFromAddr(process, threadStartAddress, NULL, symbolInfo);

    return symbolInfo->Name;
}

PVOID GetThreadStartAddress(HANDLE thread) {
    PVOID startAddress = 0;
    NtQueryInformationThread1(thread, (THREADINFOCLASS)0x09, &startAddress, sizeof(PVOID), NULL);
    return startAddress;
}

vector<HANDLE> FilterThreads(HANDLE targetProc, vector<HANDLE> procThreads) {
    vector<HANDLE> filteredThreads;

    for (HANDLE& thread : procThreads) {

        PVOID threadStartAddress = GetThreadStartAddress(thread);
        DWORD threadId = GetThreadId(thread);
        const char* name = GetThreadStartAddressSymbol(targetProc, (DWORD64)threadStartAddress);
        if (!strcmp(name, "TpReleaseCleanupGroupMembers")) {
            filteredThreads.push_back(thread);
        }
    }
    return filteredThreads;
}

int main(int argc, char* argv[]) {

    DWORD procId = GetProcessIdFromName("RobloxPlayerBeta.exe");

    if (procId == -1) {
        printf("[-] Failed To Get Process Id\n");
        return -1;
    }

    HANDLE targetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);

    if (!targetProc || targetProc == INVALID_HANDLE_VALUE) {
        printf("[-] Failed To Get Process Handle\n");
        return -1;
    }

    if (!SymInitialize(targetProc, NULL, TRUE)) {
        printf("[-] Failed To Initialize Sym\n");
        return -1;
    }

    vector<HANDLE> targetThreads = FilterThreads(targetProc, GetProcessThreads(procId));

    for (HANDLE& thread : targetThreads) {
        if (SuspendThread(thread) != -1) {
            printf("[+] Suspended Thread With Id: %ld\n", GetThreadId(thread));
        }
    }

  
}