#ifndef PEBWATCH_H
#define PEBWATCH_H

#include <windows.h>

#pragma warning(push)
#pragma warning(disable: 4200) /* zero-sized array */

/* ===================================================================
 * Manual PEB structure definitions for x64.
 * We define these ourselves because winternl.h is incomplete and
 * the offsets matter for direct memory access.
 * =================================================================== */

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

typedef struct _MY_LIST_ENTRY {
    struct _MY_LIST_ENTRY *Flink;
    struct _MY_LIST_ENTRY *Blink;
} MY_LIST_ENTRY, *PMY_LIST_ENTRY;

/*
 * LDR_DATA_TABLE_ENTRY - x64 layout
 * Offset 0x00: InLoadOrderLinks
 * Offset 0x10: InMemoryOrderLinks
 * Offset 0x20: InInitializationOrderLinks
 * Offset 0x30: DllBase
 * Offset 0x38: EntryPoint
 * Offset 0x40: SizeOfImage
 * Offset 0x48: FullDllName
 * Offset 0x58: BaseDllName
 * Offset 0x68: Flags
 * Offset 0x6C: LoadCount (ObsoleteLoadCount)
 * Offset 0x6E: TlsIndex
 * Offset 0x70: HashLinks
 * Offset 0x80: TimeDateStamp
 */
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    MY_LIST_ENTRY      InLoadOrderLinks;            /* 0x00 */
    MY_LIST_ENTRY      InMemoryOrderLinks;          /* 0x10 */
    MY_LIST_ENTRY      InInitializationOrderLinks;  /* 0x20 */
    PVOID              DllBase;                      /* 0x30 */
    PVOID              EntryPoint;                   /* 0x38 */
    ULONG              SizeOfImage;                  /* 0x40 */
    ULONG              _pad0;                        /* 0x44 alignment */
    MY_UNICODE_STRING  FullDllName;                  /* 0x48 */
    MY_UNICODE_STRING  BaseDllName;                  /* 0x58 */
    ULONG              Flags;                        /* 0x68 */
    USHORT             ObsoleteLoadCount;            /* 0x6C */
    USHORT             TlsIndex;                     /* 0x6E */
    MY_LIST_ENTRY      HashLinks;                    /* 0x70 */
    ULONG              TimeDateStamp;                /* 0x80 */
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

/*
 * PEB_LDR_DATA - x64 layout
 * Offset 0x00: Length
 * Offset 0x04: Initialized
 * Offset 0x08: SsHandle
 * Offset 0x10: InLoadOrderModuleList
 * Offset 0x20: InMemoryOrderModuleList
 * Offset 0x30: InInitializationOrderModuleList
 */
typedef struct _MY_PEB_LDR_DATA {
    ULONG          Length;                              /* 0x00 */
    BOOLEAN        Initialized;                         /* 0x04 */
    PVOID          SsHandle;                            /* 0x08 */
    MY_LIST_ENTRY  InLoadOrderModuleList;               /* 0x10 */
    MY_LIST_ENTRY  InMemoryOrderModuleList;             /* 0x20 */
    MY_LIST_ENTRY  InInitializationOrderModuleList;     /* 0x30 */
    PVOID          EntryInProgress;                     /* 0x40 */
    BOOLEAN        ShutdownInProgress;                  /* 0x48 */
    HANDLE         ShutdownThreadId;                    /* 0x50 */
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

/*
 * RTL_USER_PROCESS_PARAMETERS - x64 layout (partial)
 * Offset 0x00: MaximumLength
 * Offset 0x04: Length
 * Offset 0x08: Flags
 * Offset 0x0C: DebugFlags
 * Offset 0x10: ConsoleHandle
 * Offset 0x18: ConsoleFlags
 * Offset 0x20: StandardInput
 * Offset 0x28: StandardOutput
 * Offset 0x30: StandardError
 * Offset 0x38: CurrentDirectory (CURDIR: UNICODE_STRING + HANDLE = 0x18)
 * Offset 0x50: DllPath
 * Offset 0x60: ImagePathName
 * Offset 0x70: CommandLine
 */
typedef struct _MY_RTL_USER_PROCESS_PARAMETERS {
    ULONG              MaximumLength;       /* 0x00 */
    ULONG              Length;              /* 0x04 */
    ULONG              Flags;              /* 0x08 */
    ULONG              DebugFlags;         /* 0x0C */
    HANDLE             ConsoleHandle;      /* 0x10 */
    ULONG              ConsoleFlags;       /* 0x18 */
    ULONG              _pad0;              /* 0x1C */
    HANDLE             StandardInput;      /* 0x20 */
    HANDLE             StandardOutput;     /* 0x28 */
    HANDLE             StandardError;      /* 0x30 */
    /* CurrentDirectory is CURDIR: UNICODE_STRING (0x10) + HANDLE (0x08) = 0x18 */
    MY_UNICODE_STRING  CurrentDirectoryPath; /* 0x38 */
    HANDLE             CurrentDirectoryHandle; /* 0x48 */
    MY_UNICODE_STRING  DllPath;            /* 0x50 */
    MY_UNICODE_STRING  ImagePathName;      /* 0x60 */
    MY_UNICODE_STRING  CommandLine;        /* 0x70 */
} MY_RTL_USER_PROCESS_PARAMETERS, *PMY_RTL_USER_PROCESS_PARAMETERS;

/*
 * PEB - x64 layout (partial, fields we care about)
 * Offset 0x00: InheritedAddressSpace
 * Offset 0x01: ReadImageFileExecOptions
 * Offset 0x02: BeingDebugged
 * Offset 0x03: BitField
 * Offset 0x08: Mutant
 * Offset 0x10: ImageBaseAddress
 * Offset 0x18: Ldr
 * Offset 0x20: ProcessParameters
 * Offset 0xBC: NtGlobalFlag
 *
 * We use a byte array to pad between known fields so offsets are correct.
 */
typedef struct _MY_PEB {
    BOOLEAN                           InheritedAddressSpace;      /* 0x00 */
    BOOLEAN                           ReadImageFileExecOptions;   /* 0x01 */
    BOOLEAN                           BeingDebugged;              /* 0x02 */
    BYTE                              BitField;                   /* 0x03 */
    BYTE                              _pad0[4];                   /* 0x04 */
    PVOID                             Mutant;                     /* 0x08 */
    PVOID                             ImageBaseAddress;           /* 0x10 */
    PMY_PEB_LDR_DATA                  Ldr;                       /* 0x18 */
    PMY_RTL_USER_PROCESS_PARAMETERS   ProcessParameters;         /* 0x20 */
    BYTE                              _pad1[0x94];                /* 0x28 -> 0xBC */
    ULONG                             NtGlobalFlag;              /* 0xBC */
} MY_PEB, *PMY_PEB;

/* ===================================================================
 * Snapshot structures
 * =================================================================== */

#define MAX_MODULES        512
#define MAX_PATH_CHARS     520

typedef struct _MODULE_INFO {
    PVOID   DllBase;
    ULONG   SizeOfImage;
    ULONG   TimeDateStamp;
    WCHAR   BaseDllName[MAX_PATH_CHARS];
    WCHAR   FullDllName[MAX_PATH_CHARS];
} MODULE_INFO, *PMODULE_INFO;

typedef struct _PEB_SNAPSHOT {
    /* Module list */
    DWORD        module_count;
    MODULE_INFO  module_list[MAX_MODULES];

    /* Process parameters */
    WCHAR        image_path[MAX_PATH_CHARS];
    WCHAR        command_line[1024];

    /* Debug/flag state */
    BOOLEAN      being_debugged;
    ULONG        nt_global_flag;

    /* Snapshot metadata */
    LARGE_INTEGER timestamp;
} PEB_SNAPSHOT, *PPEB_SNAPSHOT;

typedef struct _TAMPER_REPORT {
    BOOL    modules_added;
    BOOL    modules_removed;
    DWORD   added_count;
    DWORD   removed_count;
    WCHAR   added_names[32][MAX_PATH_CHARS];
    WCHAR   removed_names[32][MAX_PATH_CHARS];
    BOOL    debug_flag_changed;
    BOOL    ntglobalflag_changed;
    BOOL    image_path_changed;
    BOOL    command_line_changed;
    BOOL    phantom_modules_detected;
    DWORD   phantom_count;
    BOOL    debug_inconsistency;
} TAMPER_REPORT, *PTAMPER_REPORT;

/* ===================================================================
 * Function declarations - peb_reader.c
 * =================================================================== */

PMY_PEB     get_peb(void);
BOOL        snapshot_peb(PPEB_SNAPSHOT snap);
DWORD       walk_module_list(PMODULE_INFO out_modules, DWORD max_count);

/* ===================================================================
 * Function declarations - tamper_detect.c
 * =================================================================== */

BOOL        compare_snapshots(const PEB_SNAPSHOT *baseline,
                              const PEB_SNAPSHOT *current,
                              PTAMPER_REPORT report);

DWORD       check_module_unlinking(const PEB_SNAPSHOT *snap);
BOOL        check_debug_consistency(void);
BOOL        check_image_path(const PEB_SNAPSHOT *snap);

#pragma warning(pop)

#endif /* PEBWATCH_H */
