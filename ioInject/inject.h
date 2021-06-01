#pragma once
#ifndef _INJECT_
#define _INJECT_

#include <ntifs.h>

extern "C"
{
	namespace Inject
	{
		// 初始化
		void InitInject();

		// KernelCallbackTable远跳转(R3:支持, R0:不支持, 此方式为被动加载)
		NTSTATUS KernelCallbackTableInjectRegistry(HANDLE pid, ULONG64 call_address);

		// APC远跳转
		// InstrumentationCallback远跳转
	}
}

#endif

