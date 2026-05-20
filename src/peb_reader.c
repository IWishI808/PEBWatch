#include "pebwatch.h"
#include <intrin.h>
#include <stdio.h>

/*
 * get_peb - Read PEB pointer from the TEB via GS segment.
 *
 * On x64 Windows, GS:0x60 holds the linear address of the PEB.
 * The TEB itself is at GS:0x30, and TEB+0x60 = ProcessEnvironmentBlock.
 */
PMY_PEB get_peb(void)
{
    return (PMY_PEB)__readgsqword(0x60);
}

/*
 * walk_module_list - Walk InLoadOrderModuleList and extract module info.
 *
 * Returns the number of modules found (capped at max_count).
 * The linked list is circular: head is PEB->Ldr->InLoadOrderModuleList,
 * each entry's InLoadOrderLinks.Flink points to the next, and we stop
 * when we loop back to the head.
 */
DWORD walk_module_list(PMODULE_INFO out_modules, DWORD max_count)
{
    PMY_PEB peb;
    PMY_PEB_LDR_DATA ldr;
    PMY_LIST_ENTRY head;
    PMY_LIST_ENTRY current;
    PMY_LDR_DATA_TABLE_ENTRY entry;
    DWORD count = 0;

    peb = get_peb();
    if (!peb || !peb->Ldr)
        return 0;

    ldr = peb->Ldr;
    head = &ldr->InLoadOrderModuleList;
    current = head->Flink;

    while (current != head && count < max_count) {
        /*
         * CONTAINING_RECORD: InLoadOrderLinks is at offset 0 of
         * LDR_DATA_TABLE_ENTRY, so the entry pointer == the list entry pointer.
         */
        entry = CONTAINING_RECORD(current, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->DllBase == NULL) {
            current = current->Flink;
            continue;
        }

        out_modules[count].DllBase = entry->DllBase;
        out_modules[count].SizeOfImage = entry->SizeOfImage;
        out_modules[count].TimeDateStamp = entry->TimeDateStamp;

        /* Copy BaseDllName */
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            USHORT copy_len = entry->BaseDllName.Length / sizeof(WCHAR);
            if (copy_len >= MAX_PATH_CHARS)
                copy_len = MAX_PATH_CHARS - 1;
            memcpy(out_modules[count].BaseDllName,
                   entry->BaseDllName.Buffer,
                   copy_len * sizeof(WCHAR));
            out_modules[count].BaseDllName[copy_len] = L'\0';
        } else {
            out_modules[count].BaseDllName[0] = L'\0';
        }

        /* Copy FullDllName */
        if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
            USHORT copy_len = entry->FullDllName.Length / sizeof(WCHAR);
            if (copy_len >= MAX_PATH_CHARS)
                copy_len = MAX_PATH_CHARS - 1;
            memcpy(out_modules[count].FullDllName,
                   entry->FullDllName.Buffer,
                   copy_len * sizeof(WCHAR));
            out_modules[count].FullDllName[copy_len] = L'\0';
        } else {
            out_modules[count].FullDllName[0] = L'\0';
        }

        count++;
        current = current->Flink;
    }

    return count;
}

/*
 * snapshot_peb - Capture a full PEB snapshot.
 *
 * Walks the module list, reads BeingDebugged, NtGlobalFlag,
 * and copies ImagePathName + CommandLine from ProcessParameters.
 */
BOOL snapshot_peb(PPEB_SNAPSHOT snap)
{
    PMY_PEB peb;
    PMY_RTL_USER_PROCESS_PARAMETERS params;

    if (!snap)
        return FALSE;

    ZeroMemory(snap, sizeof(PEB_SNAPSHOT));
    QueryPerformanceCounter(&snap->timestamp);

    peb = get_peb();
    if (!peb)
        return FALSE;

    /* Debug state */
    snap->being_debugged = peb->BeingDebugged;
    snap->nt_global_flag = peb->NtGlobalFlag;

    /* Module list */
    snap->module_count = walk_module_list(snap->module_list, MAX_MODULES);

    /* Process parameters */
    params = peb->ProcessParameters;
    if (params) {
        /* ImagePathName */
        if (params->ImagePathName.Buffer && params->ImagePathName.Length > 0) {
            USHORT copy_len = params->ImagePathName.Length / sizeof(WCHAR);
            if (copy_len >= MAX_PATH_CHARS)
                copy_len = MAX_PATH_CHARS - 1;
            memcpy(snap->image_path,
                   params->ImagePathName.Buffer,
                   copy_len * sizeof(WCHAR));
            snap->image_path[copy_len] = L'\0';
        }

        /* CommandLine */
        if (params->CommandLine.Buffer && params->CommandLine.Length > 0) {
            USHORT copy_len = params->CommandLine.Length / sizeof(WCHAR);
            if (copy_len >= 1023)
                copy_len = 1023;
            memcpy(snap->command_line,
                   params->CommandLine.Buffer,
                   copy_len * sizeof(WCHAR));
            snap->command_line[copy_len] = L'\0';
        }
    }

    return TRUE;
}
