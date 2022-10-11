# WindowsKernelUtility

## Some very useful functions implementation in Windows Kernel

Inlucding

```
namespace Utils
{
	PVOID GetModuleBase(PCHAR szModuleName);
	PVOID GetModuleBaseEx(PCHAR szModuleName);
	PVOID GetProcAddress(PVOID ModuleBase, PCHAR szFuncName);
	BOOLEAN RtlCaptureAnsiString(PUNICODE_STRING, PCSZ, BOOLEAN);
	ULONG GetActiveProcessLinksOffset();
	HANDLE GetProcessIdByName(PCHAR szName);
	PVOID GetProcessBaseAddress(int pid);
	PEPROCESS GetProcessByName(PCHAR szName);
	PETHREAD GetProcessMainThread(PEPROCESS Process);	
	ULONG64 FindPattern(ULONG64 base, SIZE_T size, PCHAR pattern, PCHAR mask);
	ULONG64 FindPatternImage(PCHAR module, PCHAR section, PCHAR pattern, PCHAR mask);
	ULONG64 GetImageSectionByName(ULONG64 imageBase, PCHAR sectionName, SIZE_T* sizeOut);
	PSERVICE_DESCRIPTOR_TABLE GetKeServiceDescriptorTableShadow();
	PVOID GetServiceFunctionByIndex(PSYSTEM_SERVICE_TABLE, ULONG ServiceId);
	ULONG GetThreadProcessOffset();
	BOOLEAN SpoofGuiThread();
	BOOLEAN UnspoofGuiThread();
	NTSTATUS ReadVirtual(ULONG64 dirbase, ULONG64 address, PBYTE buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteVirtual(ULONG64 dirbase, ULONG64 address, PBYTE buffer, SIZE_T size);
	ULONG64 GetProcessCr3(PEPROCESS pProcess);
	ULONG64 TranslateLinearAddress(ULONG64 directoryTableBase, ULONG64 virtualAddress);
	NTSTATUS ReadPhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
	NTSTATUS WritePhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size);
	NTSTATUS ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size);
	BOOLEAN SetPageProtection(PVOID VirtualAddress, SIZE_T NumberOfBytes, ULONG NewProtect);
};
```
