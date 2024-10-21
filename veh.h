#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#pragma once
#pragma pack(push)
#pragma pack(1)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BYTE Initialized;
    LPVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BYTE ShutdownInProgress;
    PVOID ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
} RTL_USER_PROCESS_PARAMETERS,*PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE BitField;
    DWORD Padding0;
    LPVOID Mutant;
    LPVOID ImageBaseAddress;

    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    LPVOID SubSystemData;
    LPVOID ProcessHeap;
    LPVOID FastPebLock;
    LPVOID AtlThunkSListPtr;        // AtlThunkSListPtr
    LPVOID IFEOKey;                 // IFEOKey
    union {                         // CrossProcessFlags
		ULONG CrossProcessFlags;
		struct {
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
		ULONG EnvironmentUpdateCount;
	};
    union {
        LPVOID   KernelCallbackTable;
        LPVOID   UserSharedInfoPtr;
    };
    DWORD SystemReserved;
    DWORD _SYSTEM_DEPENDENT_05;
    LPVOID _SYSTEM_DEPENDENT_06;
    LPVOID TlsExpansionCounter;
    LPVOID TlsBitmap;
    DWORD TlsBitmapBits[2];
    LPVOID ReadOnlySharedMemoryBase;
    LPVOID _SYSTEM_DEPENDENT_07;
    LPVOID ReadOnlyStaticServerData;
    LPVOID AnsiCodePageData;
    LPVOID OemCodePageData;
    LPVOID UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union {
        DWORD     NtGlobalFlag;
        LPVOID   dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    LPVOID HeapSegmentReserve;
    LPVOID HeapSegmentCommit;
    LPVOID HeapDeCommitTotalFreeThreshold;
    LPVOID HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    LPVOID ProcessHeaps;
    LPVOID GdiSharedHandleTable;
    LPVOID ProcessStarterHelper;
    LPVOID GdiDCAttributeList;
    LPVOID LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    LPVOID ImageSubsystemMinorVersion;
    union {
        LPVOID ImageProcessAffinityMask;
        LPVOID ActiveProcessAffinityMask;
    };
    #ifdef _WIN64
    LPVOID GdiHandleBuffer[64];
    #else
    LPVOID GdiHandleBuffer[32];
    #endif
    LPVOID PostProcessInitRoutine;
    LPVOID TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    LPVOID SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    LPVOID pShimData;
    LPVOID AppCompatInfo;
    PUNICODE_STRING CSDVersion;
    LPVOID ActivationContextData;
    LPVOID ProcessAssemblyStorageMap;
    LPVOID SystemDefaultActivationContextData;
    LPVOID SystemAssemblyStorageMap;
    LPVOID MinimumStackCommit;
} PEB, *PPEB;

#pragma pack(pop)
#pragma once

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _VECTORED_HANDLER_ENTRY {
    struct _VECTORED_HANDLER_ENTRY *pNext;
    struct _VECTORED_HANDLER_ENTRY *pPrev;
    PVOID Refs;
    ULONG Padding0;
    PVECTORED_EXCEPTION_HANDLER pVectoredHandler;
} VECTORED_HANDLER_ENTRY, *PVECTORED_HANDLER_ENTRY; 

typedef struct _VECTORED_HANDLER_LIST {
    SRWLOCK srwLock;
    VECTORED_HANDLER_ENTRY *pFirstHandler;
    VECTORED_HANDLER_ENTRY *pLastHandler;
} VECTORED_HANDLER_LIST, *PVECTORED_HANDLER_LIST; 

extern NTSTATUS NTAPI NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN OUT PSIZE_T NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
extern LPVOID WINAPI RtlAllocateHeap(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef BOOLEAN(WINAPI* RTLACQUIRESRWLOCKEXCLUSIVE)(PSRWLOCK SRWLock);
typedef BOOLEAN(WINAPI* RTLRELEASESRWLOCKEXCLUSIVE)(PSRWLOCK SRWLock);
