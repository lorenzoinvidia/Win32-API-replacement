/* 
    Adapted from https://github.com/zerosum0x0/LoadLibrary-GetProcAddress-Replacements
*/
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

/* Return ptr to PEB */
static __inline PEB __declspec(naked) __forceinline *GetPEB() {
	__asm {
		mov eax, dword ptr fs : [0x30];
		retn;
	}
}//GetPEB


/* Get module handle like */
HMODULE WINAPI xGetModuleHandle(LPCWSTR moduleName) {
	PEB *pPeb = NULL;
	LIST_ENTRY *pListEntry = NULL;
	LDR_DATA_TABLE_ENTRY *pLdrDataTableEntry = NULL;

	if ( !(pPeb = GetPEB()) ){
        printf("PEB");
        return NULL;  
    }

    // Get first module 
	pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InMemoryOrderModuleList.Flink;
	pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;
	
	do
	{
		if (lstrcmpiW(pLdrDataTableEntry->FullDllName.Buffer, moduleName) == 0)
			return (HMODULE)pLdrDataTableEntry->Reserved2[0]; // handle

        // Next node
		pListEntry = pListEntry->Flink;
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pListEntry->Flink);

	} while (pListEntry != pPeb->Ldr->InMemoryOrderModuleList.Flink);

	return NULL;
}//xGetModuleHandle


/* Get procedure address like */
FARPROC WINAPI xGetProcAddress(HMODULE hModule, const char *lpProcName){

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if ( IMAGE_DOS_SIGNATURE != pDosHeader->e_magic ){
        printf("DOS signature mismatch");
        return NULL;
    }
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)( (LPBYTE)hModule + pDosHeader->e_lfanew );
    if ( IMAGE_NT_SIGNATURE != pNtHeaders->Signature ){
        printf("PE signature mismatch");
        return NULL;
    }
    
    // DataDirectory[0] Export
    // DataDirectory[1] Import
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    // funXY at AddressOfNames[idx] has its export ordinal at AddressOfNameOrdinals[idx]
    // We use that ordinal as index to get funXY's RVA in the AddressOfFunctions
	PDWORD pNames = (PDWORD)( (LPBYTE)hModule + pExportDirectory->AddressOfNames);           //32bit
    PWORD pOrdinals = (PWORD)( (LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);   //16bit
    PDWORD pAddress = (PDWORD)( (LPBYTE)hModule + pExportDirectory->AddressOfFunctions);

	for(unsigned i=0; i<pExportDirectory->NumberOfNames; i++){
        if( !strcmp(lpProcName,(char*)hModule+pNames[i]) ){
            return (FARPROC)((LPBYTE)hModule+pAddress[pOrdinals[i]]);
        }
    }
    return NULL;
}//xGetProcAddress

typedef HMODULE(WINAPI * _LoadLibrary)(LPCSTR lpFileName);
typedef int (WINAPI * _MessageBox)(
    HWND    hWnd,
    LPCWSTR lpText,
    LPCWSTR lpCaption,
    UINT    uType
);

//typedef FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
//typedef HMODULE(WINAPI * _GetModuleHandle)(LPCWSTR lpModuleName);

int main(){

    _LoadLibrary pLoadLibrary = (_LoadLibrary)xGetProcAddress(xGetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    
    
    //_GetProcAddress xGetProcAddress(L"KERNEL32.DLL", "GetProcAddress");
    
    _MessageBox pMessageBox = (_MessageBox)xGetProcAddress(pLoadLibrary("user32.dll"), "MessageBoxW");
    pMessageBox(NULL, L"It works!", L"Hello World!", MB_OK);

    return 0;
}