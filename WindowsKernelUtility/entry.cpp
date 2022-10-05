#include "includes.h"
#include "Utils.hpp"
#include "Imports.h"

EXTERN_C NTSTATUS DriverUnload(PDRIVER_OBJECT Driver)
{
	UNREFERENCED_PARAMETER(Driver);
	return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT Driver)
{
	KdPrint(("DriverEntry\n"));
	return STATUS_SUCCESS;
}
