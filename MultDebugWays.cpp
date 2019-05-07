// MultDebugWays.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <ntstatus.h>

namespace CSZQ {
#include "ntoskrnl.h"
}

#define __CSZQDEBUG 1
#if __CSZQDEBUG > 0
#define DBGPRINT(format, ...)   printf(format,##__VA_ARGS__);
#define PRINTDBG DbgPrint("%s:%d\r\n", __FUNCTION__, __LINE__);
#else
#define DBGPRINT(format, ...)
#define PRINTDBG
#endif

/*********************************************************************************************************
	说明：
		官方方法禁止本进程发送调试信息
	参数：
		无
	返回值：
		0  成功
		-1 失败
*********************************************************************************************************/
int forbiddenDebugger(void) {
	#define ThreadHideFromDebugger 17
	typedef  NTSTATUS(__stdcall *NtSetInformationThread)(HANDLE ThreadHandle, int ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);

	NtSetInformationThread pNtSetInformationThread = 0;
	pNtSetInformationThread = (NtSetInformationThread)GetProcAddress(GetModuleHandleA("ntdll"), "ZwSetInformationThread");

	if (!pNtSetInformationThread) {
		DBGPRINT("[Error]Not find ZwSetInformationThread\r\n");
		return -1;
	}

	if (!pNtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0)) {
		DBGPRINT("[Error] ZwSetInformationThread\r\n");
		return -1;
	}
	else {
		DBGPRINT("[INFO]Forbidden debugger success!\r\n");
		return 0;
	}
}
/*********************************************************************************************************
	说明：
		枚举全部object判断是否存在调试器，不一定在调试本进程，但是存在调试器
	参数：
		无
	返回值：
		1  存在调试器
		0  不存在调试器
		-1 失败
*********************************************************************************************************/
int isGlobalDebuggerPresent(void) {

	typedef NTSTATUS(__stdcall *ZwQueryObject)(HANDLE Handle, CSZQ::OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
	
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING;

	typedef struct _OBJECT_TYPE_INFORMATION {
		UNICODE_STRING TypeName;
		ULONG TotalNumberOfObjects;
		ULONG TotalNumberOfHandles;
		ULONG TotalPagedPoolUsage;
		ULONG TotalNonPagedPoolUsage;
		ULONG TotalNamePoolUsage;
		ULONG TotalHandleTableUsage;
		ULONG HighWaterNumberOfObjects;
		ULONG HighWaterNumberOfHandles;
		ULONG HighWaterPagedPoolUsage;
		ULONG HighWaterNonPagedPoolUsage;
		ULONG HighWaterNamePoolUsage;
		ULONG HighWaterHandleTableUsage;
		ULONG InvalidAttributes;
		GENERIC_MAPPING GenericMapping;
		ULONG ValidAccessMask;
		BOOLEAN SecurityRequired;
		BOOLEAN MaintainHandleCount;
		ULONG PoolType;
		ULONG DefaultPagedPoolCharge;
		ULONG DefaultNonPagedPoolCharge;
	} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

	typedef struct _OBJECT_TYPES_INFORMATION {
		ULONG NumberOfTypes;
		OBJECT_TYPE_INFORMATION TypeInformation[1];
	} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;
	 

	DWORD dwSize = 0;
	INT   iRet = 0;
	ZwQueryObject pZwQueryObject = 0;
	POBJECT_TYPES_INFORMATION pAllInfo = 0;
	POBJECT_TYPE_INFORMATION  pTypeInfo = 0;

	pZwQueryObject = (ZwQueryObject)GetProcAddress(GetModuleHandleA("ntdll"), "ZwQueryObject");
	
	if (!pZwQueryObject) {
		DBGPRINT("[Error]Not find ZwQueryObject\r\n");
		return -1;
	}

	/*
		时刻创建删除内核对象，不一定完全匹配，建议直接给大内存
	*/
	pAllInfo = (POBJECT_TYPES_INFORMATION)VirtualAlloc(NULL, 0x10000, MEM_COMMIT, PAGE_READWRITE);
	iRet = pZwQueryObject(0, CSZQ::OBJECT_INFORMATION_CLASS::ObjectTypesInformation, 0, 0x10000, &dwSize);

	if (iRet == STATUS_INFO_LENGTH_MISMATCH || iRet == STATUS_NO_MEMORY) {
		DBGPRINT("[ERROR]ZwQueryObject : buffer too small\r\n", iRet);
		return -1;
	}
	else {
		pZwQueryObject(NULL, CSZQ::OBJECT_INFORMATION_CLASS::ObjectTypesInformation, pAllInfo, dwSize, &dwSize);
		pTypeInfo = pAllInfo->TypeInformation;
		for (int i = 0; i < pAllInfo->NumberOfTypes; i++) {
			if (pTypeInfo->TotalNumberOfHandles > 0 || pTypeInfo->TotalNumberOfObjects > 0) {
				if (!_wcsicmp(pTypeInfo->TypeName.Buffer, L"DebugObject"))
					return 1;
			}
			/*
				内存组织形式为 Typeinfo Typename   NextTypeinfo  NextTypename
			*/
			pTypeInfo = (OBJECT_TYPE_INFORMATION *)((char *)pTypeInfo->TypeName.Buffer + ((pTypeInfo->TypeName.MaximumLength + 3)&~3));
		}
	}
	return 0;
}

/*********************************************************************************************************
	说明：
		各种常见调试方法杂烩，x86平台
	参数：
		argc  参数个数
		argv  参数
	返回值：
		
*********************************************************************************************************/
int main(int argc, char* argv[])
{
	printf("Begin\r\n");

	/*
		枚举全局 obj
	*/
	if (isGlobalDebuggerPresent()) {
		printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
	}

	/*
		IsDebuggerPresent
	*/
	if (IsDebuggerPresent()) {
		printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
	}

	/*
		CheckRemoteDebuggerPresent
	*/
	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	BOOL bDebug = 0;

	CheckRemoteDebuggerPresent(hProcess, &bDebug);
	if (bDebug) {
		printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
	}

	/*
		NtGlobalFlag
	*/
	DWORD NtGlobalFlag = 0;
	_asm {
		mov eax, fs:[0x30];
		mov eax, dword ptr[eax + 0x68];
		mov NtGlobalFlag, eax;
	};
	if ((NtGlobalFlag & 0xFF) != 0x0) {                                 // 0x70
		printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
	}

	/*
		processHeap
	*/
	int Flags = 0;
	int ForceFlags = 0;

	__asm
	{
		mov eax, fs:[0x30]; //PEB地址
		mov eax, [eax + 0x18];//ProcessHeap成员
		mov ebx, [eax + 0x40];//ForceFlags成员
		mov Flags, ebx;
		mov ebx, [eax + 0x44];//ForceFlags成员
		mov ForceFlags, ebx;
	}
	if (ForceFlags != 0) {
		printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
	}

	/*
		SeDebugPrivilege
	*/
	{
		HANDLE hProcess = NULL;
		PROCESSENTRY32 Pe32 = { 0 };
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			return 0;
		}
		Pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hProcessSnap, &Pe32))
		{
			do
			{
				if (_wcsicmp(L"csrss.exe", Pe32.szExeFile) == 0)
				{
					HANDLE hProcess = OpenProcess(
						PROCESS_ALL_ACCESS,
						FALSE,
						Pe32.th32ProcessID
					);

					if (hProcess)
					{
						printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
					}
					else
					{

					}
					CloseHandle(hProcess);
				}
			} while (Process32Next(hProcessSnap, &Pe32));
		}
		CloseHandle(hProcessSnap);
	}

	/*
		硬件断点检测
	*/
	{
		BOOL bHardBreak = FALSE;
		auto Filter = [&bHardBreak](struct _EXCEPTION_POINTERS* pExceptionInfo)->int {
			if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
				if (pExceptionInfo->ContextRecord->Dr0 != 0 ||
					pExceptionInfo->ContextRecord->Dr1 != 0 ||
					pExceptionInfo->ContextRecord->Dr2 != 0 ||
					pExceptionInfo->ContextRecord->Dr3 != 0) {
					bHardBreak = TRUE;
				}
				return EXCEPTION_EXECUTE_HANDLER;
			}
			return EXCEPTION_CONTINUE_SEARCH;
		};

		__try {
			RaiseException(EXCEPTION_INT_DIVIDE_BY_ZERO, 0, 0, NULL);
		}
		__except (Filter(GetExceptionInformation())) {
			if (bHardBreak) {
				printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
			}
		}
	}

	/*
		int 3 异常处理，有调试器会当作中断而不会进入异常处理
	*/
	{
		BOOL bHardBreak = TRUE;

		auto Filter = [&bHardBreak](struct _EXCEPTION_POINTERS* pExceptionInfo)->int {
			bHardBreak = FALSE;
			return EXCEPTION_EXECUTE_HANDLER;
		};

		__try {
			_asm {
				int 3;
			}
		}
		__except (Filter(GetExceptionInformation())) {
		}
		if (bHardBreak) {
			printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
		}
	}

	/*
		利用单步异常进行检测
	*/
	__try {
		_asm {
			pushfd;
			or dword ptr[esp], 100h;
			popfd;
		}
		printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}

	/*
		int 2d
	*/
	__try
	{
		__asm
		{
			int 2dh;
			inc eax;//any opcode of singlebyte.上述指令会导致后面一个字节的指令被跳过，inte 86 指令集规定的
		}
		printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	/*
		todo:
	*/
	{
		int Flags = 0;
		__asm {
			mov eax, fs:[0x30];
			mov eax, dword ptr[eax + 0x10];
			mov eax, dword ptr[eax + 0x8];
			mov Flags, eax;
		}
		printf("Flags = 0x%08x\r\n", Flags);
	}

	/*
		NtQueryInformationProcess
	*/
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		if (!hProcess) {
			printf("[ERROR]OpenProcess Fail!\r\n");
		}
		else {

			typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
				_In_      HANDLE           ProcessHandle,
				_In_      UINT             ProcessInformationClass,
				_Out_     PVOID            ProcessInformation,
				_In_      ULONG            ProcessInformationLength,
				_Out_opt_ PULONG           ReturnLength
				);

			UINT uiProcessDebugPort = 7;
			DWORD dwIsDebuggerPresent = 0;
			HMODULE hModule = GetModuleHandle(L"ntdll.dll");
			pfnNtQueryInformationProcess pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
			if (!pNtQueryInformationProcess) {
				printf("[ERROR]pNtQueryInformationProcess = NULL\r\n");
			}
			else {
				NTSTATUS ntStatus = pNtQueryInformationProcess(
					GetCurrentProcess(),
					uiProcessDebugPort,
					&dwIsDebuggerPresent,
					sizeof(DWORD),
					NULL);
				if (ntStatus == 0x00000000 && dwIsDebuggerPresent != 0)
				{
					printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
				}
			}
		}
	}

	DebugBreak();

	printf("End\r\n");

	return 0;
}