#include "main.h"
#include "inject.h"

extern "C"
{
	DRIVER_INITIALIZE DriverEntry;
	DRIVER_UNLOAD DriverUnload;

	void KernelSleep(size_t second)
	{
		LARGE_INTEGER timeOut = RtlConvertLongToLargeInteger(-10 * 1000 * 1000 * second);
		KeDelayExecutionThread(KernelMode, FALSE, &timeOut);
	}

	NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
	{
		DriverObject->DriverUnload = DriverUnload;
		Inject::KernelCallbackTableInjectRegistry((HANDLE)0xD0C, 0x7FFF9B6D2AD0);
		//KernelSleep(10);
		//Inject::KernelCallbackTableInjectRegistry((HANDLE)0xAC0, 0x772B1314);

		return STATUS_SUCCESS;
	}

	VOID DriverUnload(PDRIVER_OBJECT DriverObject)
	{
	}
}