/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2021
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.11
*
*  DATE:        01 June 2021
*
*  Query and output ApiSet specific data.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

typedef VOID(CALLBACK* pfnApiSetQueryMap)(
    _In_ PVOID ApiSetMap, \
    _In_ HTREEITEM RootItem);

#define APISET_QUERY_ROUTINE(n) VOID n(   \
    _In_ PVOID ApiSetMap,                 \
    _In_ HTREEITEM RootItem)

/*
* DiplayErrorText
*
* Purpose:
*
* In debug build send string to debugger else show message box.
*
*/
VOID DiplayErrorText(
    _In_ LPWSTR ErrorMsg)
{
#ifdef _DEBUG
    OutputDebugString(ErrorMsg);
#else
    MessageBox(g_ctx.MainWindow, ErrorMsg, NULL, MB_ICONERROR);
#endif
}

/*
* TreeListAddItem
*
* Purpose:
*
* Insert new treelist item.
*
*/
HTREEITEM TreeListAddItem(
    _In_ HWND TreeList,
    _In_opt_ HTREEITEM hParent,
    _In_ UINT mask,
    _In_ UINT state,
    _In_ UINT stateMask,
    _In_opt_ LPWSTR pszText,
    _In_opt_ PVOID subitems
)
{
    TVINSERTSTRUCT  tvitem;
    PTL_SUBITEMS    si = (PTL_SUBITEMS)subitems;

    RtlSecureZeroMemory(&tvitem, sizeof(tvitem));
    tvitem.hParent = hParent;
    tvitem.item.mask = mask;
    tvitem.item.state = state;
    tvitem.item.stateMask = stateMask;
    tvitem.item.pszText = pszText;
    tvitem.hInsertAfter = TVI_LAST;
    return TreeList_InsertTreeItem(TreeList, &tvitem, si);
}

/*
* OutNamespaceEntryEx
*
* Purpose:
*
* Namespace entry formatted output routine.
*
*/
HTREEITEM OutNamespaceEntryEx(
    HTREEITEM RootItem,
    PBYTE Namespace,
    ULONG NameOffset,
    ULONG NameLength,
    ULONG Flags,
    BOOL FlagsValid
)
{
    TL_SUBITEMS_FIXED subitems;
    PWSTR Name, NameCopy, sptr;
    HTREEITEM hSubItem;
    WCHAR szBuffer[20];

    if (NameOffset == 0)
        return 0;

    Name = (PWSTR)RtlOffsetToPointer(Namespace, NameOffset);

    NameCopy = HeapAlloc(g_ctx.PluginHeap, HEAP_ZERO_MEMORY, NameLength + sizeof(WCHAR));
    if (NameCopy == NULL)
        return 0;

    sptr = NameCopy;

    RtlCopyMemory(
        sptr,
        Name,
        NameLength);

    sptr += (NameLength / sizeof(WCHAR));
    *sptr = 0;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    subitems.Text[0] = L"";

    if (FlagsValid && Flags) {
        szBuffer[0] = 0;
        ultostr(Flags, szBuffer);
        sptr = szBuffer;
    }
    else {
        sptr = L"";
    }
    subitems.Text[1] = sptr;

    subitems.Count = 2;

    hSubItem = TreeListAddItem(
        g_ctx.TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        NameCopy,
        &subitems);

    HeapFree(g_ctx.PluginHeap, 0, NameCopy);
    return hSubItem;
}

/*
* OutNamespaceValueEx
*
* Purpose:
*
* Namespace value formatted output routine.
*
*/
void OutNamespaceValueEx(
    HTREEITEM RootItem,
    PBYTE Namespace,
    ULONG ValueOffset,
    ULONG ValueLength,
    ULONG NameOffset,
    ULONG NameLength,
    ULONG Flags,
    BOOL FlagsValid
)
{
    TL_SUBITEMS_FIXED  subitems;
    PWSTR NamePtr, ValueName = NULL, AliasName = NULL, sptr = NULL;
    WCHAR szBuffer[20];

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    // print value name

    if (ValueLength) {

        NamePtr = (PWSTR)RtlOffsetToPointer(Namespace, ValueOffset);

        ValueName = HeapAlloc(g_ctx.PluginHeap, HEAP_ZERO_MEMORY, ValueLength + sizeof(WCHAR));
        if (ValueName) {
            sptr = ValueName;

            RtlCopyMemory(
                sptr,
                NamePtr,
                ValueLength);

            sptr += (ValueLength / sizeof(WCHAR));
            *sptr = 0;

        }
    }

    // print value alias
    if (NameLength) {

        NamePtr = (PWSTR)RtlOffsetToPointer(Namespace, NameOffset);

        AliasName = HeapAlloc(g_ctx.PluginHeap, HEAP_ZERO_MEMORY, NameLength + sizeof(WCHAR));
        if (AliasName) {
            sptr = AliasName;

            RtlCopyMemory(
                sptr,
                NamePtr,
                NameLength);

            sptr += (NameLength / sizeof(WCHAR));
            *sptr = 0;

            sptr = AliasName;

        }
    }
    else {
        sptr = L"";
    }
    subitems.Text[0] = sptr;

    if (FlagsValid && Flags) {
        szBuffer[0] = 0;
        ultostr(Flags, szBuffer);
        sptr = szBuffer;
    }
    else {
        sptr = L"";
    }
    subitems.Text[1] = sptr;
    subitems.Count = 2;

    TreeListAddItem(
        g_ctx.TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        ValueName,
        &subitems);

    if (ValueName) HeapFree(g_ctx.PluginHeap, 0, ValueName);
    if (AliasName) HeapFree(g_ctx.PluginHeap, 0, AliasName);
}

/*
* ListApiSetV2
*
* Purpose:
*
* Parse and output ApiSet Version 2 (Windows 7).
*
*/
APISET_QUERY_ROUTINE(ListApiSetV2)
{
    API_SET_NAMESPACE_ARRAY_V2* Namespace = (API_SET_NAMESPACE_ARRAY_V2*)ApiSetMap;

    ULONG i, j;

    API_SET_NAMESPACE_ENTRY_V2* NsEntry;
    API_SET_VALUE_ARRAY_V2* ValuesArray;
    API_SET_VALUE_ENTRY_V2* ValueEntry;

    HTREEITEM hSubItem;

    for (i = 0; i < Namespace->Count; i++) {

        NsEntry = &Namespace->Array[i];

        hSubItem = OutNamespaceEntryEx(
            RootItem,
            (PBYTE)Namespace,
            NsEntry->NameOffset,
            NsEntry->NameLength,
            0,
            FALSE);

        ValuesArray = (API_SET_VALUE_ARRAY_V2*)RtlOffsetToPointer(Namespace, NsEntry->DataOffset);

        for (j = 0; j < ValuesArray->Count; j++) {

            ValueEntry = &ValuesArray->Array[j];

            if (!API_SET_EMPTY_NAMESPACE_VALUE(ValueEntry)) {
                OutNamespaceValueEx(
                    hSubItem,
                    (PBYTE)Namespace,
                    ValueEntry->ValueOffset,
                    ValueEntry->ValueLength,
                    ValueEntry->NameOffset,
                    ValueEntry->NameLength,
                    0,
                    FALSE);
            }
        }
    }
}

/*
* ListApiSetV4
*
* Purpose:
*
* Parse and output ApiSet Version 4 (Windows 8.x).
*
*/
APISET_QUERY_ROUTINE(ListApiSetV4)
{
    API_SET_NAMESPACE_ARRAY_V4* Namespace = (API_SET_NAMESPACE_ARRAY_V4*)ApiSetMap;

    ULONG i, j;

    API_SET_NAMESPACE_ENTRY_V4* NsEntry;
    API_SET_VALUE_ARRAY_V4* ValuesArray;
    API_SET_VALUE_ENTRY_V4* ValueEntry;

    HTREEITEM hSubItem;

    for (i = 0; i < Namespace->Count; i++) {

        NsEntry = &Namespace->Array[i];

        hSubItem = OutNamespaceEntryEx(
            RootItem,
            (PBYTE)Namespace,
            NsEntry->NameOffset,
            NsEntry->NameLength,
            NsEntry->Flags,
            TRUE);

        ValuesArray = (API_SET_VALUE_ARRAY_V4*)RtlOffsetToPointer(Namespace, NsEntry->DataOffset);

        for (j = 0; j < ValuesArray->Count; j++) {

            ValueEntry = &ValuesArray->Array[j];

            if (!API_SET_EMPTY_NAMESPACE_VALUE(ValueEntry)) {
                OutNamespaceValueEx(
                    hSubItem,
                    (PBYTE)Namespace,
                    ValueEntry->ValueOffset,
                    ValueEntry->ValueLength,
                    ValueEntry->NameOffset,
                    ValueEntry->NameLength,
                    ValueEntry->Flags,
                    TRUE);
            }
        }
    }
}

/*
* ListApiSetV6
*
* Purpose:
*
* Parse and output ApiSet Version 6 (Windows 10).
*
*/
APISET_QUERY_ROUTINE(ListApiSetV6)
{
    API_SET_NAMESPACE_ARRAY_V6* Namespace = (API_SET_NAMESPACE_ARRAY_V6*)ApiSetMap;

    ULONG i, j;

    API_SET_NAMESPACE_ENTRY_V6* NsEntry;
    API_SET_VALUE_ENTRY_V6* ValueEntry;

    HTREEITEM hSubItem;

    NsEntry = (API_SET_NAMESPACE_ENTRY_V6*)RtlOffsetToPointer(Namespace, Namespace->NamespaceEntryOffset);

    for (i = 0; i < Namespace->Count; i++) {

        hSubItem = OutNamespaceEntryEx(
            RootItem,
            (PBYTE)Namespace,
            NsEntry->NameOffset,
            NsEntry->NameLength,
            NsEntry->Flags,
            TRUE);

        ValueEntry = (API_SET_VALUE_ENTRY_V6*)RtlOffsetToPointer(Namespace, NsEntry->DataOffset);

        for (j = 0; j < NsEntry->Count; j++) {

            if (!API_SET_EMPTY_NAMESPACE_VALUE(ValueEntry)) {
                OutNamespaceValueEx(
                    hSubItem,
                    (PBYTE)Namespace,
                    ValueEntry->ValueOffset,
                    ValueEntry->ValueLength,
                    ValueEntry->NameOffset,
                    ValueEntry->NameLength,
                    ValueEntry->Flags,
                    TRUE);
            }
            ValueEntry = (API_SET_VALUE_ENTRY_V6*)RtlOffsetToPointer(ValueEntry, sizeof(API_SET_VALUE_ENTRY_V6));
        }
        NsEntry = (API_SET_NAMESPACE_ENTRY_V6*)RtlOffsetToPointer(NsEntry, sizeof(API_SET_NAMESPACE_ENTRY_V6));
    }
}

/*
* ResolveDllData
*
* Purpose:
*
* Process apiset file, locate apiset section and schema version.
*
*/
BOOL ResolveDllData(
    _In_ HMODULE DllHandle,
    _Inout_ PVOID* ApiSetData,
    _Out_ PULONG SchemaVersion
)
{
    ULONG dataSize = 0;
    UINT i;
    ULONG schemaVersion = 0;

    PIMAGE_NT_HEADERS ntHeaders;
    IMAGE_SECTION_HEADER* sectionTableEntry;
    PBYTE baseAddress;
    PBYTE dataPtr = NULL;

    *SchemaVersion = 0;

    baseAddress = (PBYTE)(((ULONG_PTR)DllHandle) & ~3);

    ntHeaders = RtlImageNtHeader(baseAddress);

    sectionTableEntry = IMAGE_FIRST_SECTION(ntHeaders);

    i = ntHeaders->FileHeader.NumberOfSections;
    while (i > 0) {
        if (_strncmpi_a((CHAR*)&sectionTableEntry->Name,
            API_SET_SECTION_NAME,
            sizeof(API_SET_SECTION_NAME)) == 0)
        {
            dataSize = sectionTableEntry->SizeOfRawData;
            dataPtr = (PBYTE)RtlOffsetToPointer(baseAddress, sectionTableEntry->PointerToRawData);
            break;
        }
        i -= 1;
        sectionTableEntry += 1;
    }

    if (dataPtr == NULL || dataSize == 0) {
        return FALSE;
    }

    schemaVersion = *(ULONG*)dataPtr;

    *SchemaVersion = schemaVersion;
    *ApiSetData = dataPtr;

    return TRUE;
}

/*
* ListApiSetFromFileWorker
*
* Purpose:
*
* Processing apiset file.
*
*/
VOID WINAPI ListApiSetFromFileWorker(
    _In_ LPCWSTR SchemaFileName,
    _In_ PVOID ApiSetData,
    _In_ ULONG SchemaVersion
)
{
    pfnApiSetQueryMap queryMapRoutine;

    WCHAR szBuffer[MAX_PATH * 2];

    HTREEITEM h_tviRootItem;

    //
    // Disable controls.
    //
    EnableWindow(GetDlgItem(g_ctx.MainWindow, IDC_BROWSE_BUTTON), FALSE);
    EnableWindow(GetDlgItem(g_ctx.MainWindow, IDC_SEARCH_BUTTON), FALSE);

    //
    // Reset output controls.
    //
    TreeList_ClearTree(g_ctx.TreeList);
    SetDlgItemText(g_ctx.MainWindow, IDC_SCHEMA_FILE, SchemaFileName);

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    ultostr(SchemaVersion, szBuffer);
    SetDlgItemText(g_ctx.MainWindow, IDC_SCHEMA_VERSION, szBuffer);

    TreeList_RedrawDisable(g_ctx.TreeList);

    //
    // Parse and output apiset.
    //
    h_tviRootItem = TreeListAddItem(
        g_ctx.TreeList,
        (HTREEITEM)NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        TEXT("ApiSetSchema"),
        (PVOID)NULL);

    if (h_tviRootItem) {

        switch (SchemaVersion) {

        case API_SET_SCHEMA_VERSION_V2:
            queryMapRoutine = (pfnApiSetQueryMap)ListApiSetV2;
            break;

        case API_SET_SCHEMA_VERSION_V4:
            queryMapRoutine = (pfnApiSetQueryMap)ListApiSetV4;
            break;

        case API_SET_SCHEMA_VERSION_V6:
            queryMapRoutine = (pfnApiSetQueryMap)ListApiSetV6;
            break;

        default:
            queryMapRoutine = NULL;
            break;
        }

        __try {

            if (queryMapRoutine)
                queryMapRoutine(ApiSetData, h_tviRootItem);

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

            szBuffer[0] = 0;

            StringCchPrintf(
                szBuffer,
                MAX_PATH,
                TEXT("ApiSetView: Exception %lu thrown while processing apiset, schema version %lu"),
                GetExceptionCode(),
                SchemaVersion);

            DiplayErrorText(szBuffer);

        }
    }

    //
    // Reenable controls.
    //
    EnableWindow(GetDlgItem(g_ctx.MainWindow, IDC_BROWSE_BUTTON), TRUE);
    EnableWindow(GetDlgItem(g_ctx.MainWindow, IDC_SEARCH_BUTTON), TRUE);
    TreeList_RedrawEnableAndUpdateNow(g_ctx.TreeList);
}

/*
* ListApiSetFromFile
*
* Purpose:
*
* Load file or use default system apiset and output it contents.
*
*/
VOID ListApiSetFromFile(
    _In_opt_ LPCWSTR FileName)
{
    ULONG cch;
    ULONG schemaVersion = 0;
    HMODULE hApiSetDll;
    LPWSTR lpFileName = NULL;
    PVOID dataPtr = NULL;
    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szSystemDirectory[MAX_PATH + 1];

    //
    // Select apiset dll name.
    //
    if (FileName) {
        lpFileName = (LPWSTR)FileName;
    }
    else {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        RtlSecureZeroMemory(szSystemDirectory, sizeof(szSystemDirectory));
        cch = GetSystemDirectory(szSystemDirectory, MAX_PATH);
        if (cch && cch < MAX_PATH) {
            StringCchPrintf(szBuffer, MAX_PATH, TEXT("%s\\apisetschema.dll"), szSystemDirectory);
            lpFileName = szBuffer;
        }
    }

    if (lpFileName == NULL) {
        DiplayErrorText(TEXT("ApiSet dll filename not specified"));
        return;
    }

    //
    // Load library and locate apiset section.
    //

    hApiSetDll = LoadLibraryEx(lpFileName, NULL, LOAD_LIBRARY_AS_DATAFILE);

    if (hApiSetDll) {

        if (ResolveDllData(hApiSetDll, &dataPtr, &schemaVersion)) {

            if (schemaVersion != API_SET_SCHEMA_VERSION_V2 &&
                schemaVersion != API_SET_SCHEMA_VERSION_V4 &&
                schemaVersion != API_SET_SCHEMA_VERSION_V6)
            {
                StringCchPrintf(szBuffer, MAX_PATH,
                    TEXT("ApiSetView: Unknown schema version %lu"), schemaVersion);

                DiplayErrorText(szBuffer);
            }
            else {
                ListApiSetFromFileWorker(lpFileName, dataPtr, schemaVersion);
            }
        }
        else {
            DiplayErrorText(TEXT("ApiSetView: could not resolve data, probably not apiset file or data corrupted"));
        }

        FreeLibrary(hApiSetDll);
    }
    else {
        DiplayErrorText(TEXT("ApiSetView: could not load apiset library"));
    }
}
