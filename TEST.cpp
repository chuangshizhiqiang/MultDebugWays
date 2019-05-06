// TEST.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>


int main()
{
	printf("Begin\r\n");

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
	if ((NtGlobalFlag & 0xFF) == 0x70) {
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
			inc eax;//any opcode of singlebyte.上述指令会导致后面一个字节的指令被跳过
		}
		printf("[DEBUG]%s:%d\r\n", __func__, __LINE__);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		
	}
	
	{
		int Flags = 0;
		__asm {
			mov eax, fs:[0x30];
			mov eax, dword ptr [eax + 0x10];
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


	printf("End\r\n");
	
	return 0;
}
