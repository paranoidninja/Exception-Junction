#include "veh.h"

UINT_PTR findNtdll() {
	UINT_PTR hModule = __readgsqword(0x60);
	hModule = *(UINT_PTR*)(hModule + 0x18);
	hModule = *(UINT_PTR*)(hModule + 0x10);
	hModule = *(UINT_PTR*)(hModule);
	hModule = *(UINT_PTR*)(hModule + 0x30);
	return hModule;
}

PVOID GetLdrpVectorHandlerList() {
    // Byte pattern for LdrpVectorHandlerList for windows 10 is: 48 83 EC 20 44 8B ? ? 8D ? ? ? ? ? 48 8B E9
    // Pattern to search for: 0x4883EC20448BF24C8D254EEB0F00 (last 4 bytes are the offset)
    const BYTE pattern[] = { 0x48, 0x83, 0xEC, 0x20, 0x44, 0x8B, 0xF2, 0x4C, 0x8D, 0x25 };
    const size_t patternLength = sizeof(pattern);
    UINT_PTR hNtdll = findNtdll();

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER textSection = IMAGE_FIRST_SECTION(ntHeader);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (strncmp((const char*)textSection->Name, ".text", 5) == 0) {
            break;
        }
        textSection++;
    }
    BYTE* textSectionStart = (BYTE*)hNtdll + textSection->VirtualAddress;
    DWORD textSectionSize = textSection->Misc.VirtualSize;
    for (DWORD i = 0; i < textSectionSize - patternLength; i++) {
        if (memcmp(textSectionStart + i, pattern, patternLength) == 0) {
            int32_t offset = *(int32_t*)(textSectionStart + i + patternLength);
            BYTE* instruction_after_offset = textSectionStart + i + patternLength + 4;
            BYTE* ldrpVehList = instruction_after_offset + offset;
            return ldrpVehList;
        }
    }
    return NULL;
}

LONG CALLBACK ExceptionHook(PEXCEPTION_POINTERS ExceptionInfo) {
    printf("[+] Breakpoint Exception Caught. Success!\n");
    ExitProcess(0);
}

PVECTORED_HANDLER_ENTRY RtlpAddVectoredExceptionHandler(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER pVectoredHandler) {
    LPVOID mrDataAddr = NULL;
    SIZE_T mrDataSize = 0;
    ULONG oldProtect = 0;
    HMODULE hNtdll = (HMODULE) findNtdll();
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (strncmp((const char*)section->Name, ".mrdata", 7) == 0) {
            mrDataAddr = (PBYTE)hNtdll + section->VirtualAddress;
            mrDataSize = section->Misc.VirtualSize;
            break;
        }
    }

    PPEB pPeb = (PPEB) __readgsqword(0x60);
    PVECTORED_HANDLER_ENTRY pNewVehEntry = (PVECTORED_HANDLER_ENTRY)RtlAllocateHeap((HANDLE)pPeb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(VECTORED_HANDLER_ENTRY));
    PVOID refsBuffer = RtlAllocateHeap((HANDLE)pPeb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(PVOID));
    *(int*)refsBuffer = 1;
    pNewVehEntry->Refs = refsBuffer;

    PVOID encodedHandler = EncodePointer((PVOID)pVectoredHandler);

    RTLACQUIRESRWLOCKEXCLUSIVE RtlAcquireSRWLockExclusive = (RTLACQUIRESRWLOCKEXCLUSIVE) GetProcAddress(hNtdll, "RtlAcquireSRWLockExclusive");
    RTLRELEASESRWLOCKEXCLUSIVE RtlReleaseSRWLockExclusive = (RTLRELEASESRWLOCKEXCLUSIVE) GetProcAddress(hNtdll, "RtlReleaseSRWLockExclusive");
    PVECTORED_HANDLER_LIST LdrpVectorHandlerList = (PVECTORED_HANDLER_LIST) GetLdrpVectorHandlerList();
    if (LdrpVectorHandlerList) {
        printf("[+] LdrpVectorHandlerList: 0x%p\n", LdrpVectorHandlerList);
    } else {
        printf("[-] LdrpVectorHandlerList not found.\n");
        ExitProcess(0);
    }
    PSRWLOCK pLdrpVehLock = *(PSRWLOCK*) (&LdrpVectorHandlerList->srwLock);
    RtlAcquireSRWLockExclusive(pLdrpVehLock);
    pNewVehEntry->pVectoredHandler = (PVECTORED_EXCEPTION_HANDLER)encodedHandler;

    //If the list is empty then set the CrossProcessFlags fields
    if(LdrpVectorHandlerList->pFirstHandler == (PVECTORED_HANDLER_ENTRY)&LdrpVectorHandlerList->pFirstHandler) {
        InterlockedBitTestAndSet((LONG *)&pPeb->CrossProcessFlags, 2); // 'lock bts, dword ptr ds:[rax+50], ecx'
    }

    NtProtectVirtualMemory((HANDLE)-1, &mrDataAddr, &mrDataSize, PAGE_READWRITE, &oldProtect); // can replace this with LdrProtectMrData
    if(FirstHandler) { //Add new node to the head of VEH
        pNewVehEntry->pNext = LdrpVectorHandlerList->pFirstHandler;
        pNewVehEntry->pPrev = (PVECTORED_HANDLER_ENTRY)&LdrpVectorHandlerList->pFirstHandler;
        LdrpVectorHandlerList->pFirstHandler->pPrev = pNewVehEntry;
        LdrpVectorHandlerList->pFirstHandler = pNewVehEntry;
    } else { //Add new node to the end of VEH
        pNewVehEntry->pNext = (PVECTORED_HANDLER_ENTRY)&LdrpVectorHandlerList->pFirstHandler;
        pNewVehEntry->pPrev = LdrpVectorHandlerList->pLastHandler;
        LdrpVectorHandlerList->pLastHandler->pNext = pNewVehEntry;
        LdrpVectorHandlerList->pLastHandler = pNewVehEntry;
    }
    NtProtectVirtualMemory((HANDLE)-1, &mrDataAddr, &mrDataSize, oldProtect, &oldProtect);
    RtlReleaseSRWLockExclusive(pLdrpVehLock);
    return pNewVehEntry;
}

int main() {
    RtlpAddVectoredExceptionHandler(0x1, ExceptionHook);
    printf("[+] Added handler. Checking if exception is caught\n");
    __debugbreak();
    return 0;
}
