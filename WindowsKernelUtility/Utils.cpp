#include "Utils.hpp"
#include "Imports.h"

PVOID Utils::GetModuleBase(PCHAR szModuleName)
{
	PVOID result = 0;
	ULONG length = 0;

	ZwQuerySystemInformation(SystemModuleInformation, &length, 0, &length);
	if (!length) return result;

	const unsigned long tag = 'MEM';
	PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (!system_modules) return result;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, system_modules, length, 0);
	if (NT_SUCCESS(status))
	{
		for (size_t i = 0; i < system_modules->ulModuleCount; i++)
		{
			char* fileName = (char*)system_modules->Modules[i].ImageName + system_modules->Modules[i].ModuleNameOffset;
			if (!strcmp(fileName, szModuleName))
			{
				result = system_modules->Modules[i].Base;
				break;
			}
		}
	}
	ExFreePoolWithTag(system_modules, tag);
	return result;
}

BOOLEAN Utils::RtlCaptureAnsiString(PUNICODE_STRING DestinationString, PCSZ SourceString, BOOLEAN AllocateDestinationString)
{
    ANSI_STRING ansi_string = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    RtlInitAnsiString(&ansi_string, SourceString);
    status = RtlAnsiStringToUnicodeString(DestinationString, &ansi_string, AllocateDestinationString);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }
    return TRUE;
}

PVOID Utils::GetModuleBaseEx(PCHAR szModuleName)
{
    UNICODE_STRING uName = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
    PLIST_ENTRY PsLoadedModuleList, NextEntry;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    UNICODE_STRING uModuleName = { 0 };
    
    PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&uName);
    if (!MmIsAddressValid(PsLoadedModuleList))
    {
        return NULL;
    }
    RtlCaptureAnsiString(&uModuleName, szModuleName, TRUE);

    /* Lookup the new Ldr entry in PsLoadedModuleList */
    for (NextEntry = PsLoadedModuleList->Flink;
        NextEntry != PsLoadedModuleList;
        NextEntry = NextEntry->Flink)
    {
        LdrEntry = (PLDR_DATA_TABLE_ENTRY)NextEntry;
        DbgPrint("module = %wZ\n", &LdrEntry->BaseDllName);
        if (RtlEqualUnicodeString(&uModuleName, &LdrEntry->BaseDllName, TRUE))
        {
            return LdrEntry->DllBase;
        }
    }
    return NULL;
}

PVOID Utils::GetProcAddress(PVOID ModuleBase, PCHAR szFuncName)
{
	return RtlFindExportedRoutineByName(ModuleBase, szFuncName);
}

ULONG Utils::GetActiveProcessLinksOffset()
{
    UNICODE_STRING FunName = { 0 };
    RtlInitUnicodeString(&FunName, L"PsGetProcessId");

    /*
    .text:000000014007E054                   PsGetProcessId  proc near
    .text:000000014007E054
    .text:000000014007E054 48 8B 81 80 01 00+                mov     rax, [rcx+180h]
    .text:000000014007E054 00
    .text:000000014007E05B C3                                retn
    .text:000000014007E05B                   PsGetProcessId  endp
    */

    PUCHAR pfnPsGetProcessId = (PUCHAR)MmGetSystemRoutineAddress(&FunName);
    if (pfnPsGetProcessId && MmIsAddressValid(pfnPsGetProcessId) && MmIsAddressValid(pfnPsGetProcessId + 0x7))
    {
        for (size_t i = 0; i < 0x7; i++)
        {
            if (pfnPsGetProcessId[i] == 0x48 && pfnPsGetProcessId[i + 1] == 0x8B)
            {
                return *(PULONG)(pfnPsGetProcessId + i + 3) + 8;
            }
        }
    }
    return 0;
}

HANDLE Utils::GetProcessIdByName(PCHAR szName)
{
    PEPROCESS Process = GetProcessByName(szName);
    if (Process)
    {
        return PsGetProcessId(Process);
    }
    return NULL;
}

PEPROCESS Utils::GetProcessByName(PCHAR szName)
{
    PEPROCESS Process = NULL;
    PCHAR ProcessName = NULL;
    PLIST_ENTRY pHead = NULL;
    PLIST_ENTRY pNode = NULL;

    ULONG64 ActiveProcessLinksOffset = GetActiveProcessLinksOffset();
    //KdPrint(("ActiveProcessLinksOffset = %llX\n", ActiveProcessLinksOffset));
    if (!ActiveProcessLinksOffset)
    {
        KdPrint(("GetActiveProcessLinksOffset failed\n"));
        return NULL;
    }
    Process = PsGetCurrentProcess();

    pHead = (PLIST_ENTRY)((ULONG64)Process + ActiveProcessLinksOffset);
    pNode = pHead;

    do
    {
        Process = (PEPROCESS)((ULONG64)pNode - ActiveProcessLinksOffset);
        ProcessName = PsGetProcessImageFileName(Process);
        //KdPrint(("%s\n", ProcessName));
        if (!strcmp(szName, ProcessName))
        {
            return Process;
        }

        pNode = pNode->Flink;
    } while (pNode != pHead);

    return NULL;
}


PETHREAD Utils::GetProcessMainThread(PEPROCESS Process)
{
    PETHREAD ethread = NULL;
    KAPC_STATE kApcState = { 0 };
    HANDLE hThread = NULL;

    KeStackAttachProcess(Process, &kApcState);
    NTSTATUS status = ZwGetNextThread(NtCurrentProcess(), NULL, THREAD_ALL_ACCESS,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, &hThread);

    if (NT_SUCCESS(status))
    {

        status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS,
            *PsThreadType, KernelMode, (PVOID*)&ethread, NULL);
        NtClose(hThread);

        if (!NT_SUCCESS(status))
        {
            ethread = NULL;
        }
    }
    KeUnstackDetachProcess(&kApcState);
    return ethread;
}


ULONG64 Utils::FindPattern(ULONG64 base, SIZE_T size, PCHAR pattern, PCHAR mask)
{
    const auto patternSize = strlen(mask);

    for (size_t i = 0; i < size - patternSize; i++) {
        for (size_t j = 0; j < patternSize; j++) {
            if (mask[j] != '?' && *reinterpret_cast<PBYTE>(base + i + j) != static_cast<BYTE>(pattern[j]))
                break;

            if (j == patternSize - 1)
                return (ULONG64)base + i;
        }
    }
    return 0;
}

ULONG64 Utils::FindPatternImage(PCHAR module, PCHAR section, PCHAR pattern, PCHAR mask)
{
    uintptr_t ModuleBase = 0;
    size_t SectionSize = 0;

    ModuleBase = (uintptr_t)GetModuleBase(module);
    if (!ModuleBase)
        return 0;

    const auto SectionBase = GetImageSectionByName(ModuleBase, section, &SectionSize);
    if (!SectionBase)
        return 0;

    return FindPattern(SectionBase, SectionSize, pattern, mask);
}


ULONG64 Utils::GetImageSectionByName(ULONG64 imageBase, PCHAR sectionName, SIZE_T* sizeOut)
{
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D)
        return 0;

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
    const auto sectionCount = ntHeader->FileHeader.NumberOfSections;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG64)(ntheader) +                                            \
     FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +                   \
     ((ntheader))->FileHeader.SizeOfOptionalHeader))

    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    for (size_t i = 0; i < sectionCount; ++i, ++sectionHeader) {
        if (!strcmp(sectionName, reinterpret_cast<const char*>(sectionHeader->Name))) {
            if (sizeOut)
                *sizeOut = sectionHeader->Misc.VirtualSize;
            return imageBase + sectionHeader->VirtualAddress;
        }
    }
    return 0;
}


PSERVICE_DESCRIPTOR_TABLE Utils::GetKeServiceDescriptorTableShadow()
{
    auto keServiceDescriptorTableShadow = FindPatternImage("ntoskrnl.exe", ".text",
        "\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F", "xxxxxxxxx");
    if (!keServiceDescriptorTableShadow)
        return 0;

    keServiceDescriptorTableShadow += 21;
    keServiceDescriptorTableShadow += *reinterpret_cast<int*>(keServiceDescriptorTableShadow) + sizeof(int);

    return (PSERVICE_DESCRIPTOR_TABLE)keServiceDescriptorTableShadow;
}


PVOID Utils::GetServiceFunctionByIndex(PSYSTEM_SERVICE_TABLE ServiceTable, ULONG ServiceId)
{
    PULONG ServiceTableBase = (PULONG)ServiceTable->ServiceTable;
    if (!MmIsAddressValid(ServiceTableBase))
        return NULL;
    return (PVOID)((ULONG64)(ServiceTableBase) + (ServiceTableBase[ServiceId & 0xFFF] >> 4));
}


ULONG Utils::GetThreadProcessOffset()
{
    UNICODE_STRING FuncName = RTL_CONSTANT_STRING(L"PsGetThreadProcess");
    PVOID pfnPsGetThreadProcess = MmGetSystemRoutineAddress(&FuncName);
    if (!MmIsAddressValid(pfnPsGetThreadProcess))
        return 0;
    return *(PULONG)((PUCHAR)pfnPsGetThreadProcess + 3);
}

PEPROCESS MaskProcess;
PVOID MaskWin32Thread;
PEPROCESS OriginalProcess;
PVOID OriginalWin32Thread;
KAPC_STATE apc_state;

BOOLEAN Utils::SpoofGuiThread()
{
    MaskProcess = Utils::GetProcessByName("dwm.exe");
    PETHREAD Thread = Utils::GetProcessMainThread(MaskProcess);
    if (PsIsThreadTerminating(Thread))
        return FALSE;

    MaskWin32Thread = PsGetThreadWin32Thread(Thread);
    if (!MaskWin32Thread)
    {
        KdPrint(("Failed to Get Win32Thread\n"));
        return FALSE;
    }

    PKTHREAD currentThread = KeGetCurrentThread();

    OriginalProcess = PsGetThreadProcess(currentThread);
    OriginalWin32Thread = PsGetCurrentThreadWin32Thread();

    KeStackAttachProcess(MaskProcess, &apc_state);

    PsSetThreadWin32Thread(currentThread, MaskWin32Thread, PsGetCurrentThreadWin32Thread());
    *(PEPROCESS*)((char*)currentThread + GetThreadProcessOffset()) = MaskProcess;

    return TRUE;
}

BOOLEAN Utils::UnspoofGuiThread()
{
    PKTHREAD currentThread = KeGetCurrentThread();

    PsSetThreadWin32Thread(currentThread, OriginalWin32Thread, PsGetCurrentThreadWin32Thread());
    *(PEPROCESS*)((char*)currentThread + GetThreadProcessOffset()) = OriginalProcess;

    KeUnstackDetachProcess(&apc_state);
    return TRUE;
}

PVOID Utils::GetProcessBaseAddress(int pid)
{
    PEPROCESS pProcess = NULL;
    if (pid == 0) return NULL;

    NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
    if (NtRet != STATUS_SUCCESS) return NULL;

    PVOID Base = PsGetProcessSectionBaseAddress(pProcess);
    ObDereferenceObject(pProcess);
    return Base;
}

//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

DWORD GetUserDirectoryTableBaseOffset()
{
    RTL_OSVERSIONINFOW ver = { 0 };
    RtlGetVersion(&ver);

    switch (ver.dwBuildNumber)
    {
    case WINDOWS_1803:
        return 0x0278;
        break;
    case WINDOWS_1809:
        return 0x0278;
        break;
    case WINDOWS_1903:
        return 0x0280;
        break;
    case WINDOWS_1909:
        return 0x0280;
        break;
    case WINDOWS_2004:
        return 0x0388;
        break;
    case WINDOWS_20H2:
        return 0x0388;
        break;
    case WINDOWS_21H1:
        return 0x0388;
        break;
    default:
        return 0x0388;
    }
}

ULONG64 Utils::GetProcessCr3(PEPROCESS pProcess)
{
    PUCHAR process = (PUCHAR)pProcess;
    ULONG64 process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
    if (process_dirbase == 0)
    {
        DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
        ULONG64 process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
        return process_userdirbase;
    }
    return process_dirbase;
}

NTSTATUS Utils::ReadVirtual(ULONG64 dirbase, ULONG64 address, PBYTE buffer, SIZE_T size, SIZE_T* read)
{
    ULONG64 paddress = TranslateLinearAddress(dirbase, address);
    return ReadPhysicalAddress(paddress, buffer, size, read);
}

NTSTATUS Utils::WriteVirtual(ULONG64 dirbase, ULONG64 address, PBYTE buffer, SIZE_T size)
{
    ULONG64 paddress = TranslateLinearAddress(dirbase, address);
    return WritePhysicalAddress(paddress, buffer, size);
}

NTSTATUS Utils::ReadPhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
    MM_COPY_ADDRESS AddrToRead = { 0 };
    AddrToRead.PhysicalAddress.QuadPart = TargetAddress;
    return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS Utils::WritePhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size)
{
    if (!TargetAddress)
        return STATUS_UNSUCCESSFUL;

    PHYSICAL_ADDRESS AddrToWrite = { 0 };
    AddrToWrite.QuadPart = TargetAddress;

    PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

    if (!pmapped_mem)
        return STATUS_UNSUCCESSFUL;

    memcpy(pmapped_mem, lpBuffer, Size);

    MmUnmapIoSpace(pmapped_mem, Size);
    return STATUS_SUCCESS;
}

#define PAGE_OFFSET_SIZE 12
static const ULONG64 PMASK = (~0xfull << 8) & 0xfffffffffull;

ULONG64 Utils::TranslateLinearAddress(ULONG64 directoryTableBase, ULONG64 virtualAddress) 
{
    directoryTableBase &= ~0xf;

    ULONG64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
    ULONG64 pte = ((virtualAddress >> 12) & (0x1ffll));
    ULONG64 pt = ((virtualAddress >> 21) & (0x1ffll));
    ULONG64 pd = ((virtualAddress >> 30) & (0x1ffll));
    ULONG64 pdp = ((virtualAddress >> 39) & (0x1ffll));

    SIZE_T readsize = 0;
    ULONG64 pdpe = 0;
    ReadPhysicalAddress(directoryTableBase + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
    if (~pdpe & 1)
        return 0;

    ULONG64 pde = 0;
    ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde), &readsize);
    if (~pde & 1)
        return 0;

    /* 1GB large page, use pde's 12-34 bits */
    if (pde & 0x80)
        return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

    ULONG64 pteAddr = 0;
    ReadPhysicalAddress((pde & PMASK) + 8 * pt, &pteAddr, sizeof(pteAddr), &readsize);
    if (~pteAddr & 1)
        return 0;

    /* 2MB large page */
    if (pteAddr & 0x80)
        return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

    virtualAddress = 0;
    ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof(virtualAddress), &readsize);
    virtualAddress &= PMASK;

    if (!virtualAddress)
        return 0;

    return virtualAddress + pageOffset;
}

NTSTATUS Utils::ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
    PEPROCESS pProcess = NULL;
    if (pid == 0) return STATUS_UNSUCCESSFUL;

    NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
    if (NtRet != STATUS_SUCCESS) return NtRet;

    ULONG64 process_dirbase = GetProcessCr3(pProcess);
    ObDereferenceObject(pProcess);

    SIZE_T CurOffset = 0;
    SIZE_T TotalSize = size;
    while (TotalSize)
    {
        ULONG64 CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
        if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

        ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
        SIZE_T BytesRead = 0;
        NtRet = ReadPhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
        TotalSize -= BytesRead;
        CurOffset += BytesRead;
        if (NtRet != STATUS_SUCCESS) break;
        if (BytesRead == 0) break;
    }

    *read = CurOffset;
    return NtRet;
}

NTSTATUS Utils::WriteProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size)
{
    PEPROCESS pProcess = NULL;
    if (pid == 0) return STATUS_UNSUCCESSFUL;

    NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
    if (NtRet != STATUS_SUCCESS) return NtRet;

    ULONG64 process_dirbase = GetProcessCr3(pProcess);
    ObDereferenceObject(pProcess);

    SIZE_T CurOffset = 0;
    SIZE_T TotalSize = size;
    while (TotalSize)
    {
        ULONG64 CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
        if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

        ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
        SIZE_T BytesWritten = 0;
        NtRet = WritePhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize);
        TotalSize -= BytesWritten;
        CurOffset += BytesWritten;
        if (NtRet != STATUS_SUCCESS) break;
        if (BytesWritten == 0) break;
    }
    return NtRet;
}

BOOLEAN Utils::SetPageProtection(PVOID VirtualAddress, SIZE_T NumberOfBytes, ULONG NewProtect)
{
    typedef BOOLEAN(*pfnMmSetPageProtection)(__in_bcount(NumberOfBytes) PVOID VirtualAddress, SIZE_T NumberOfBytes, ULONG NewProtect);
    pfnMmSetPageProtection MmSetPageProtection = NULL;

    MmSetPageProtection = (pfnMmSetPageProtection)(Utils::FindPatternImage("ntoskrnl.exe", ".text",
        "\x41\x8B\xD8\x4C\x8B\xFA\x4C\x8B\xF1\x33\xD2\x41\xB8\x00\x00\x00\x00\x48\x8D\x4C\x24\x00\xE8\x00\x00\x00\x00\x49\x8B\xCE",
        "xxxxxxxxxxxxx????xxxx?x????xxx") - 0x25);
    return MmSetPageProtection(VirtualAddress, NumberOfBytes, NewProtect);
}