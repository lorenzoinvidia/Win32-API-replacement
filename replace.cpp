/* **********************************************************************
*  PoC: replace.cpp
*  Author: lorenzoinvidia
*
*  Description:
*  Shellcoding-like resolve function address without imports
*
* **********************************************************************
* */


/* 
    Adapted from https://github.com/zerosum0x0/LoadLibrary-GetProcAddress-Replacements
*/
#include <Windows.h>
#include <winternl.h>
#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#endif //DEBUG
#define MAX_BUFF 20

/* Return ptr to PEB */
static __inline PEB __declspec(naked) __forceinline *GetPEB() {
	__asm {
		mov eax, dword ptr fs : [0x30];
		retn;
	}
}//GetPEB


/*
  stcmp like 
  https://stackoverflow.com/questions/34873209/implementation-of-strcmp#34873406
 */
int eqstrcmp(char str1[], char str2[]) {
    for (int i = 0; ; i++){
        if (str1[i] != str2[i]) return str1[i] < str2[i] ? -1 : 1;
        if (str1[i] == '\0') return 0;
    }
}//eqstrcmp

 
/*
  wcscmp like
 */
int eqwcsmp(const wchar_t *str1, const wchar_t *str2) {
    for (int i = 0; ; i++) {
        if (str1[i] != str2[i]) return str1[i] < str2[i] ? -1 : 1;
        if (str1[i] == L'\0') return 0;
    }
}//eqwcsmp



/* Get module handle like */
HMODULE WINAPI eqGetModuleHandle(PWCHAR lowerName) {
	PEB *pPeb = NULL;
	LIST_ENTRY *pListEntry = NULL;
	LDR_DATA_TABLE_ENTRY *pLdrDataTableEntry = NULL;

    WCHAR upper[MAX_BUFF] = {0};
    int offset = L'a' - L'A';

    for(unsigned i=0; lowerName[i]; i++){
        upper[i] = lowerName[i];
        if (lowerName[i] >= L'a') upper[i] -= offset;
    }


    if ( !(pPeb = GetPEB()) ) return NULL;

    // Get first module 
	pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InMemoryOrderModuleList.Flink;
	pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;

	
	do {
        if (!eqwcsmp(pLdrDataTableEntry->FullDllName.Buffer, lowerName) ||
            !eqwcsmp(pLdrDataTableEntry->FullDllName.Buffer, upper) ||
            !eqwcsmp(pLdrDataTableEntry->FullDllName.Buffer, upper) ){
            return (HMODULE)pLdrDataTableEntry->Reserved2[0]; // handle
        }
        // Next node
		pListEntry = pListEntry->Flink;
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pListEntry);

	} while (pListEntry != pPeb->Ldr->InMemoryOrderModuleList.Flink);

	return NULL;
}//eqGetModuleHandle


/* Get procedure address like */
FARPROC WINAPI eqGetProcAddress(HMODULE hModule, char *lpProcName) {

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (IMAGE_DOS_SIGNATURE != pDosHeader->e_magic) {
#ifdef DEBUG
        printf("DOS signature mismatch");
#endif //DEBUG
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDosHeader->e_lfanew);
    if (IMAGE_NT_SIGNATURE != pNtHeaders->Signature) {
#ifdef DEBUG
        printf("PE signature mismatch");
#endif //DEBUG
        return NULL;
    }

    // DataDirectory[0] Export
    // DataDirectory[1] Import
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // funXY at AddressOfNames[idx] has its export ordinal at AddressOfNameOrdinals[idx]
    // We use that ordinal as index to get funXY's RVA in the AddressOfFunctions
    PDWORD pNames = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNames);           //32bit
    PWORD pOrdinals = (PWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);   //16bit
    PDWORD pAddress = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfFunctions);

    for (unsigned i = 0; i<pExportDirectory->NumberOfNames; i++) {
        if (eqstrcmp(lpProcName, (char*)hModule + pNames[i]) == 0) {
            return (FARPROC)((LPBYTE)hModule + pAddress[pOrdinals[i]]);
        }
    }
    return NULL;
}//eqGetProcAddress

typedef HMODULE(WINAPI * _LoadLibrary)(LPCSTR lpFileName);
typedef int (WINAPI * _MessageBox)(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
);

typedef FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
//typedef HMODULE(WINAPI * _GetModuleHandle)(LPCWSTR lpModuleName);

int main(){
    WCHAR __wKernel32[]       = {L'k',L'e',L'r',L'n',L'e',L'l',L'3',L'2',L'.',L'd',L'l',L'l',0};
    WCHAR __wNtdll[]          = {L'n',L't',L'd',L'l',L'l','.','d','l','l',0};
   // HMODULE hNtdll            = eqGetModuleHandle(__wNtdll);
    HMODULE hk32              = eqGetModuleHandle(__wKernel32);
    _LoadLibrary pLoadLibrary = (_LoadLibrary)eqGetProcAddress(hk32, "LoadLibraryA");
    //_GetProcAddress pGetProcAddress = (_GetProcAddress)eqGetProcAddress(eqGetModuleHandle(__wKernel32), "GetProcAddress");
    
    _MessageBox pMessageBox = (_MessageBox)eqGetProcAddress(pLoadLibrary("user32.dll"), "MessageBoxA");
    pMessageBox(NULL, "World", "Hello", MB_OK);

    return 0;
}