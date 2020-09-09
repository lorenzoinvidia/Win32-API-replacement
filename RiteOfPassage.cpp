/* **********************************************************************
 *	PoC: Rite of Passage	
 *	Author: lorenzoinvidia
 *
 *  Description:
 *	We want to call NtReadVirtualMemory without calling it directly.
 *	To do so, we load the syscall number (0x3F) in EAX and land into 
 *	NtYieldExecution + 0x5. This func does nothing and gets no params.
 *
 *	Compile: cl /EHsc rop.cpp
 *
 * ********************************************************************** 
 * */

#include <Windows.h>
#include <stdio.h>

#define ROP		// Uncomment to use Rite of passage

typedef NTSTATUS (NTAPI* _NtReadVirtualMemory)(
	_In_ HANDLE               ProcessHandle,
	_In_ PVOID                BaseAddress,
	_Out_ PVOID               Buffer,
	_In_ ULONG                NumberOfBytesToRead,
	_Out_ PULONG              NumberOfBytesReaded OPTIONAL
);

HMODULE hNtdll = GetModuleHandleA("ntdll");
_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
DWORD NtYieldExecution_5 = (DWORD)GetProcAddress(hNtdll, "NtYieldExecution") +0x5;

int main(){

	char src[6] = "Hello";
	char dst[6] = {0};
	ULONG BytesReaded=0;
	NTSTATUS res = 0;

#ifdef ROP
	__asm {
		lea ebx, BytesReaded 
		push ebx				// NumberOfBytesReaded
		push 0x6				// NumberOfBytesToRead
		lea ebx, dst
		push ebx				// Buffer
		lea ebx, src
		push ebx				// BaseAddress
		push -1 				// ProcessHandle
		mov eax, 0x3F
		call NtYieldExecution_5
		mov res, eax
		add esp, 0x14			// Clean the stack
	}
#else
	res = NtReadVirtualMemory((HANDLE)-1, src, dst, 6, &BytesReaded);
#endif //ROP
	if (res || !BytesReaded){
		printf("fail\r\n");
		return EXIT_FAILURE;
	} 
	printf("Readed %d bytes\r\n", BytesReaded);
    return EXIT_SUCCESS;
}