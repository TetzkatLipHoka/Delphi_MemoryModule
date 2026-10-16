unit MemoryModule;

{ * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
  * Memory DLL loading code
  * ------------------------
  *
  * Original C Code
  * Memory DLL loading code
  * Version 0.0.4
  *
  * Copyright ( c ) 2004-2015 by Joachim Bauch / mail@joachim-bauch.de
  * http://www.joachim-bauch.de
  *
  * The contents of this file are subject to the Mozilla Public License Version
  * 2.0 ( the "License" ); you may not use this file except in compliance with
  * the License. You may obtain a copy of the License at
  * http://www.mozilla.org/MPL/
  *
  * Software distributed under the License is distributed on an "AS IS" basis,
  * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
  * for the specific language governing rights and limitations under the
  * License.
  *
  * The Original Code is MemoryModule.c
  *
  * The Initial Developer of the Original Code is Joachim Bauch.
  *
  * Portions created by Joachim Bauch are Copyright ( C ) 2004-2015
  * Joachim Bauch. All Rights Reserved.
  *
  * ================== MemoryModule "Conversion to Delphi" ==================
  *
  * Copyright ( c ) 2015 by Fr0sT / https://github.com/Fr0sT-Brutal
  *
  * Initially based on the code by:
  *   Copyright ( c ) 2005 - 2006 by Martin Offenwanger / coder@dsplayer.de / http://www.dsplayer.de
  *   Carlo Pasolini / cdpasop@hotmail.it / http://pasotech.altervista.org
  *
  * NOTE
  *   This code is Delphi translation of original C code taken from https://github.com/fancycode/MemoryModule
  *     ( commit dc173ca from Mar 1, 2015 ).
  *   Tested with Delphi 12.3, Windows 10/11, x86/x64.
  *
  * ================== Extensions beyond the original port ==================
  *
  *   Since the original 2015 translation this unit has grown a set of opt-in ( off by default unless
  *   noted ) features, mostly ports of "MemoryModulePP" ( MIT License, Copyright ( c ) 2020 Boring -
  *   see the `MemoryModulePP-master` folder alongside this file for the upstream C++ source and its
  *   own LICENSE/README ) plus original work. Every feature is a `$DEFINE` near the top of this file's
  *   interface section, each with its own doc comment there; this is just an index. Full investigation
  *   history, measurements, and open items: `TODO.md` in this project's folder.
  *
  *   - ALLOW_LOAD_FILES / LOAD_FROM_RESOURCE ( on by default ) - load from a file path or an embedded
  *     resource, not just a raw memory buffer.
  *   - GetModuleHandle ( on by default ) - tracks loaded modules by source ( data pointer / file name /
  *     resource name ) for MemoryGetModuleHandle and the features below that build on it.
  *   - MEMORY_DEPENDENCIES - resolve a memory/resource DLL's imports from other memory/resource DLLs
  *     instead of falling back to disk.
  *   - MEMORY_REFCOUNT - reference-count MemoryLoadLibrary/MemoryFreeLibrary by source, mirroring real
  *     LoadLibrary/FreeLibrary, instead of every call being a fully independent load.
  *   - REGISTER_IN_PEB / REGISTER_IN_BASE_ADDRESS_INDEX - link a memory-loaded module into the PEB
  *     module lists / ntdll's LdrpModuleBaseAddressIndex red-black tree, so the OS loader can attribute
  *     addresses and names to it like a real module.
  *   - MEMORY_LDR_HASH_TABLE - make memory-loaded modules resolvable by name via GetModuleHandle
  *     ( requires REGISTER_IN_PEB ).
  *   - MEMORY_SEH_X86 ( x86 ) / MEMORY_FROM_ADDRESS_X64 ( x64 ) - register a memory-loaded module in
  *     ntdll's private LdrpInvertedFunctionTable, needed for x86 SEH validation and for
  *     GetModuleHandleEx( FROM_ADDRESS )/RtlPcToFileHeader on both architectures.
  *   - MEMORY_HANDLE_TLS ( x86/x64, incl. WOW64 ) - real per-thread TLS ( threadvar /
  *     __declspec( thread ) ) for a memory-loaded module, via ntdll's own
  *     LdrpHandleTlsData/LdrpReleaseTlsEntry. x86 locator measured on Windows 11 24H2 only so far.
  *
  *   Full x86 SEH support ( a memory-loaded, non-/SAFESEH module's own exception handlers surviving )
  *   and .NET/CLR hosting are NOT implemented - see TODO.md items 2 and 4 for why, and what would be
  *   needed.
  * }

interface

{.$DEFINE FastMM4} // FastMM4 Version
{.$DEFINE FastMM5} // FastMM5 Version

{.$DEFINE LZMA}

{$DEFINE MANIFEST} // WinSxS Support
{$DEFINE ALLOW_LOAD_FILES}
{$DEFINE LOAD_FROM_RESOURCE}
{$IF Defined( LOAD_FROM_RESOURCE ) AND ( NOT Defined( FastMM4 ) AND NOT Defined( FastMM5 ) )}
  {$DEFINE USE_STREAMS} 
{$IFEND}

{$DEFINE GetModuleHandle_BuildImportTable} // Try GetModuleHandle for BuildImportTable

{$DEFINE GetModuleHandle}
{$IF Defined( GetModuleHandle ) AND ( NOT Defined( FastMM4 ) AND NOT Defined( FastMM5 ) )}
  {$DEFINE UnloadAllOnFinalize} // Unload all Modules during Finalization of this Unit
  {$DEFINE GetModuleHandleCriticalSection} // Thread-Safe
{$IFEND GetModuleHandle}

{.$DEFINE REGISTER_IN_PEB} // Link memory-loaded modules into the PEB module lists
// INCOMPLETE - does NOT fix the x86 SEH problem on its own. Measured on Windows 11 26200:
//   - the entry IS reachable by walking PEB->Ldr->InLoadOrderModuleList, but
//   - GetModuleHandleEx(FROM_ADDRESS) and GetModuleFileName(base) still fail with 126.
// Since Windows 8 the address->module lookup (LdrpFindLoadedDllByAddress) uses the red-black tree
// LdrpModuleBaseAddressIndex, not these lists - and that lookup is what RtlIsValidHandler consults
// when deciding whether an SEH handler is legitimate. A handler inside a module the loader cannot
// attribute is DISCARDED, so on x86 every try/except inside a memory-loaded module fails and the
// process dies (measured: a vectored handler sees the exception, the module's handler never runs).
// The documented escape hatch (ProcessExecuteFlags / ImageDispatchEnable) is unavailable: DEP comes
// up PERMANENT, and NtSetInformationProcess returns STATUS_ACCESS_DENIED - also without NX_COMPAT.
// Completing this requires additionally inserting the module into that tree (RtlRbInsertNodeEx and
// RtlRbRemoveNode are exported by ntdll; the tree address and the offset of BaseAddressIndexNode
// inside LDR_DATA_TABLE_ENTRY have to be located at runtime).
// x64 needs none of this for SEH - RtlAddFunctionTable already provides what unwinding needs - but
// it turns out RtlAddFunctionTable does NOT make FROM_ADDRESS work; see MEMORY_FROM_ADDRESS_X64.
// Note: this manipulates undocumented loader structures. It is opt-in for that reason.

{.$DEFINE REGISTER_IN_BASE_ADDRESS_INDEX} // requires REGISTER_IN_PEB. Additionally insert into
// ntdll!LdrpModuleBaseAddressIndex, the red-black tree the loader uses since Windows 8 for
// address->module lookup (LdrpFindLoadedDllByAddress). That lookup is what GetModuleHandleEx
// (FROM_ADDRESS), GetModuleFileName and RtlIsValidHandler consult - REGISTER_IN_PEB alone only
// fixes the list walks, which is why those APIs still failed. This is the port of MemoryModulePP's
// BaseAddressIndex.cpp + the locator from Initialize.cpp::FindLdrpModuleBaseAddressIndex.
// Best-effort and Windows 8+ only: if the tree or the ntdll helpers cannot be located the feature
// silently disables itself. Manipulating the tree races with the loader when other threads load or
// unload DLLs concurrently; the original C++ accepts this too.
{$IFDEF REGISTER_IN_BASE_ADDRESS_INDEX}
  {$IFNDEF REGISTER_IN_PEB}
    {$MESSAGE ERROR 'REGISTER_IN_BASE_ADDRESS_INDEX requires REGISTER_IN_PEB (enable it as well)'}
  {$ENDIF}
{$ENDIF}

{.$DEFINE MEMORY_DEPENDENCIES} // Resolve a memory/resource DLL's imports from other memory/resource DLLs
// MEMORY_DEPENDENCIES requires GetModuleHandle (the ModuleManager) and, for the resource path,
// LOAD_FROM_RESOURCE. A dependency is resolved in this order: (1) an already-loaded memory module,
// (2) an explicitly registered name via MemoryRegisterDllData, (3) an RT-'DLL' resource named like the
// import (existing convention). Only if none match does it fall back to the on-disk loader as before.
// Memory dependencies stay resident (owned by the ModuleManager, freed on finalization / UnloadAll).

{.$DEFINE MEMORY_SEH_X86} // x86 only: register memory modules in ntdll!LdrpInvertedFunctionTable so SEH works
// On x86, Windows validates every SEH handler against ntdll's private LdrpInvertedFunctionTable. A
// memory-loaded module is not in it, so its exception handlers are rejected and any exception raised
// inside (or passing through) the module terminates the process. This option ports the MemoryModulePP
// approach: locate that undocumented table by pattern-scanning ntdll and insert/remove the module's
// entry, exactly as the loader does internally. It is best-effort and version-specific (Win7 vs Win8+
// layouts); if the table cannot be located the feature silently disables and the module still loads
// (just without x86 exception support). x64 needs none of this for SEH - RtlAddFunctionTable already
// covers unwinding there - but see MEMORY_FROM_ADDRESS_X64 for a *different* problem on x64.

{.$DEFINE MEMORY_FROM_ADDRESS_X64} // x64 only: register memory modules in ntdll!LdrpInvertedFunctionTable
// so GetModuleHandleEx(FROM_ADDRESS)/RtlPcToFileHeader find them. Found by decompiling ntdll.dll with
// IDA (no debugger was available): those two APIs do NOT consult the loader's module lists or the
// LdrpModuleBaseAddressIndex red-black tree (REGISTER_IN_BASE_ADDRESS_INDEX) at all. They resolve
// address->module through RtlpxLookupFunctionTable - the x64 SEH *unwind* function-table lookup - whose
// fast path binary-searches a private, fixed 512-entry ntdll array (LdrpInvertedFunctionTable) that
// only the loader itself populates. This is a DIFFERENT table from the one the public RtlAddFunctionTable
// API writes to (already called unconditionally on x64 for exception unwinding, see
// RegisterExceptionTable) - confirmed empirically that RtlAddFunctionTable succeeding does not help.
// There is a slow, universal fallback path (NtQueryVirtualMemory/MemoryImageInformation, which would
// accept any genuine image mapping) but it only activates once the fixed 512-entry table has overflowed
// at least once in this process - never, in practice, for any reasonably sized process - so it cannot be
// relied on. This option locates that table (pattern-scan ntdll's .mrdata section for ntdll's own
// entry - always index 0, reserved) and inserts/removes the module's entry, mirroring ntdll's own
// (unexported) RtlpInsertInvertedFunctionTableEntry. Best-effort: if the table or its expected layout
// (verified against a live Windows 10.0.26100 process) cannot be located, the feature silently disables
// and the module still loads (just without FROM_ADDRESS support). See TODO.md item 1 for the full
// investigation. Requires an image with a non-empty exception directory (true for every normal x64 PE).
{$IF Defined( MEMORY_FROM_ADDRESS_X64 ) AND NOT Defined( CPUX64 )}
  {$UNDEF MEMORY_FROM_ADDRESS_X64} // x64-only; silently disabled on x86 so a shared defines block
  // works for multi-platform builds without editing this unit per target (same convention as
  // MEMORY_SEH_X86, which is already x86-only via its own body guard further down).
{$IFEND}

{$IFDEF MANIFEST}
  {$OPTIMIZATION OFF}
{$ENDIF}

{.$DEFINE MEMORY_HANDLE_TLS} // requires REGISTER_IN_PEB + REGISTER_IN_BASE_ADDRESS_INDEX
// Real dynamic TLS *data* for memory-loaded modules (threadvar / __declspec(thread)). The PEB
// registration gives a memory module a fake LDR entry and the base address index makes the loader
// attribute addresses to it, but neither gives the module a TLS index or per-thread TLS storage:
// threadvar in a memory-loaded DLL reads uninitialized/stale memory. This option asks ntdll's own
// LdrpHandleTlsData / LdrpReleaseTlsEntry (the same routines LoadLibrary invokes) to set up the
// module's TLS template. Port of MemoryModulePP's MmpLdrpTls.cpp (the direct-call LdrpTls path,
// no Detours). x64: locates LdrpHandleTlsData/LdrpReleaseTlsEntry via a string+C_SCOPE_TABLE
// pattern, Windows 10.0+ only (the old Win7/8 patterns without a release routine are useless).
// x86 (incl. WOW64): locates the same two routines via an AOB/wildcard scan of their own machine
// code (no release-routine-existence gate needed - the scan itself is the existence check);
// measured on two Windows 11 24H2 builds, not yet confirmed on Windows 10 - see TODO.md.
// Best-effort either way: if the routines cannot be located the feature silently disables itself.
// Verified on x86/WOW64 (2026-10-15) against both the real motivating case (SignoTec STPadLib,
// the module's own loading thread calling an export) and a synthetic MSVC test DLL covering a
// SEPARATE thread created after the load - read, write and isolation all correct, matching x64
// parity exactly (TlsCallbackCount, isolated values, clean MemoryFreeLibrary). An initial run of
// the second test crashed; root-caused to a pre-existing calling-convention bug in the TEST
// HARNESS itself (Test/Tls/TlsTest.dpr declared a 1-argument C export `stdcall` when the C side
// had no explicit convention and so defaulted to `cdecl` - invisible on x64, where both
// conventions are identical, but a real stack-cleanup mismatch on x86), not in this feature; see
// TODO.md for the full investigation.
{$IFDEF MEMORY_HANDLE_TLS}
  {$IFNDEF REGISTER_IN_PEB}
    {$MESSAGE ERROR 'MEMORY_HANDLE_TLS requires REGISTER_IN_PEB (enable it as well)'}
  {$ENDIF}
  {$IFNDEF REGISTER_IN_BASE_ADDRESS_INDEX}
    {$MESSAGE ERROR 'MEMORY_HANDLE_TLS requires REGISTER_IN_BASE_ADDRESS_INDEX (enable it as well)'}
  {$ENDIF}
{$ENDIF}

{.$DEFINE MEMORY_LDR_HASH_TABLE} // requires REGISTER_IN_PEB
// Make memory-loaded modules visible to GetModuleHandle(name)/GetModuleHandleEx by name and to
// GetModuleFileName. LoadLibrary publishes each module in ntdll's LdrpHashTable (LDR_HASH_TABLE_ENTRIES
// = 32 buckets, head entry per module is HashLinks, the LIST_ENTRY at offset 0x70 of the LDR data table
// entry on x64); LdrGetDllHandle (and thus GetModuleHandle) only walks that table, never the three
// doubly-linked lists, so a memory module that is only in the lists is invisible to name lookups.
// This option locates LdrpHashTable (pattern-free: scan InInitializationOrderModuleList for the first
// module whose HashLinks link points back to a list head, then back-compute the table start from the
// bucket index implied by its BaseDllName hash, validated by walking all 32 buckets) and inserts the
// fake entry's HashLinks into bucket LdrHashEntry(BaseDllName) (RtlUpcaseUnicodeChar-style first-char
// hash on Win8+), removing it again on unload and re-linking when UpdatePEBName changes the module's
// name. Port of MemoryModulePP's FindLdrpHashTable/IsValidLdrpHashTable/RtlInsertMemoryTableEntry.
// Best-effort: if the table cannot be located the feature silently disables itself.
{$IFDEF MEMORY_LDR_HASH_TABLE}
  {$IFNDEF REGISTER_IN_PEB}
    {$MESSAGE ERROR 'MEMORY_LDR_HASH_TABLE requires REGISTER_IN_PEB (enable it as well)'}
  {$ENDIF}
{$ENDIF}

{.$DEFINE MEMORY_REFCOUNT} // requires GetModuleHandle. Reference-count MemoryLoadLibrary/MemoryFreeLibrary
// by identity, mirroring real LoadLibrary/FreeLibrary: calling MemoryLoadLibrary/MemoryLoadLibraryFile/
// the resource overload again with the SAME source (same Data pointer, same file name, or same resource
// name) returns the ALREADY-loaded PMemoryModule and bumps its RefCount instead of mapping a second,
// independent copy; MemoryFreeLibrary decrements RefCount and only actually tears the module down
// (PEB/SEH/TLS unregistration, VirtualFree, ModuleManager removal) once it reaches zero. Without this,
// every MemoryLoadLibrary call is fully independent even for an identical source, so N callers "loading"
// the same module end up with N separate mappings, and the first MemoryFreeLibrary call from any one of
// them tears the whole thing down under the other N-1. Also wired into MEMORY_DEPENDENCIES's existing
// ResolveMemoryDependency reuse path (an already-loaded dependency shared across multiple importers now
// bumps RefCount too), so a shared dependency survives until every importer has freed it. Only applies to
// the "normal load" path (no LOAD_LIBRARY_AS_DATAFILE / _EXCLUSIVE / DONT_RESOLVE_DLL_REFERENCES /
// LOAD_LIBRARY_AS_IMAGE_RESOURCE flag) - the same condition that already gates whether a load gets
// tracked by the ModuleManager at all; calls using those flags are unaffected (always independent, as
// before).
{$IFDEF MEMORY_REFCOUNT}
  {$IFNDEF GetModuleHandle}
    {$MESSAGE ERROR 'MEMORY_REFCOUNT requires GetModuleHandle (enable it as well)'}
  {$ENDIF}
{$ENDIF}

{$WARN UNSAFE_TYPE OFF}
{$WARN UNSAFE_CODE OFF}
{$WARN UNSAFE_CAST OFF}
{$WARN COMBINING_SIGNED_UNSIGNED OFF}

// To compile under FPC, Delphi mode must be used
// Also define CPUX64 for simplicity
{$IFDEF FPC}
  {$mode delphi}
  {$IFDEF CPU64}
    {$DEFINE CPUX64}
  {$ENDIF}
{$ENDIF}

{$IFNDEF FPC}
{$IF CompilerVersion >= 23}
  {$LEGACYIFEND ON}
  {$WARN IMPLICIT_STRING_CAST OFF}
{$ELSE}
  {$RANGECHECKS OFF} // RangeCheck might cause Internal-Error C1118
{$IFEND}
{$ENDIF}

uses
  Windows;

type
{$IF NOT DECLARED( PIMAGE_NT_HEADERS32 )}
  PIMAGE_NT_HEADERS32 = ^IMAGE_NT_HEADERS;
{$ELSE}
  PIMAGE_NT_HEADERS32 = ^IMAGE_NT_HEADERS32;
{$IFEND}

{$IF NOT DECLARED( IMAGE_NT_HEADERS64 )}
  _IMAGE_OPTIONAL_HEADER64 = record
    { Standard fields. }
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    { NT additional fields. }
    ImageBase: ULONGLONG;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: ULONGLONG;
    SizeOfStackCommit: ULONGLONG;
    SizeOfHeapReserve: ULONGLONG;
    SizeOfHeapCommit: ULONGLONG;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: packed array[0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1] of TImageDataDirectory;
  end;
  IMAGE_OPTIONAL_HEADER64 = _IMAGE_OPTIONAL_HEADER64;
  PIMAGE_OPTIONAL_HEADER64 = ^IMAGE_OPTIONAL_HEADER64;

  _IMAGE_NT_HEADERS64 = record
    Signature: DWORD;
    FileHeader: TImageFileHeader;
    OptionalHeader: IMAGE_OPTIONAL_HEADER64;
  end;
  IMAGE_NT_HEADERS64 = _IMAGE_NT_HEADERS64;

  PIMAGE_NT_HEADERS64 = ^IMAGE_NT_HEADERS64;
{$ELSE}
  PIMAGE_NT_HEADERS64 = ^IMAGE_NT_HEADERS64;
{$IFEND}

  TMemoryModuleModules = record
    Handle : HMODULE;
    {$IFDEF GetModuleHandle_BuildImportTable}
    Free   : boolean;
    {$ENDIF GetModuleHandle_BuildImportTable}
  end;

  TIMAGE_NT_HEADERS3264 = packed record
    X64 : Boolean;
    case Boolean of
      False : ( headers32 : PIMAGE_NT_HEADERS32 );
      True  : ( headers64 : PIMAGE_NT_HEADERS64 );
  end;
  PIMAGE_NT_HEADERS3264 = TIMAGE_NT_HEADERS3264;

  TMemoryModule = record
    headers     : PIMAGE_NT_HEADERS3264;
    codeBase    : Pointer; // ModuleHandle
    modules     : array of TMemoryModuleModules;
    initialized : Boolean;
    isRelocated : Boolean;
    pageSize    : Cardinal;
    funcTable   : Pointer; // x64: .pdata table registered via RtlAddFunctionTable ( nil if none )
    ldrEntry    : Pointer; // REGISTER_IN_PEB: our LDR_DATA_TABLE_ENTRY ( nil if not registered )
    {$IFDEF MEMORY_REFCOUNT}
    refCount    : Integer; // MEMORY_REFCOUNT: callers currently sharing this module ( set to 1 on first load, incremented on reuse, MemoryFreeLibrary tears down only once decremented to <= 0 )
    {$ENDIF MEMORY_REFCOUNT}
    {$IFDEF MEMORY_HANDLE_TLS}
    tlsHandled  : Boolean; // MEMORY_HANDLE_TLS: true once LdrpHandleTlsData succeeded for the module
    {$ENDIF MEMORY_HANDLE_TLS}
    {$IF Defined( MEMORY_SEH_X86 ) AND NOT Defined( CPUX64 )}
    sehX86Registered : Boolean; // x86: true once inserted into LdrpInvertedFunctionTable
    {$IFEND}
    {$IF Defined( MEMORY_FROM_ADDRESS_X64 ) AND Defined( CPUX64 )}
    faX64Registered : Boolean; // x64: true once inserted into LdrpInvertedFunctionTable ( FROM_ADDRESS )
    {$IFEND}
  end;
  PMemoryModule = ^TMemoryModule;

{$IF NOT DECLARED( LOAD_LIBRARY_AS_IMAGE_RESOURCE )}
const
  LOAD_LIBRARY_AS_IMAGE_RESOURCE     = $00000020;
{$IFEND}
{$IF NOT DECLARED( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE )}
const
  LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = $00000040;
{$IFEND}

{$IF NOT DECLARED( IMAGE_FILE_MACHINE_AMD64 )}
const
  IMAGE_FILE_MACHINE_AMD64          = $8664;  { AMD64 (K8) }
{$IFEND}

  { ++++++++++++++++++++++++++++++++++++++++++++++++++
    ***  Memory DLL loading functions Declaration  ***
    -------------------------------------------------- }

// return value is nil if function fails
function MemoryLoadLibrary( data: Pointer; var Module : PMemoryModule; Flags : Cardinal = 0 ): ShortInt; stdcall; {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}overload;{$IFEND}
{$IFDEF ALLOW_LOAD_FILES}
function MemoryLoadLibraryFile( FileName : string; var Module : PMemoryModule; Flags : Cardinal = 0 ): ShortInt; stdcall;
{$ENDIF ALLOW_LOAD_FILES}
{$IFDEF LOAD_FROM_RESOURCE}
function MemoryLoadLibrary( ResourceName : string; var Module : PMemoryModule; {$IFDEF USE_STREAMS}Password : string = '';{$ENDIF} Flags : Cardinal = 0 ): ShortInt; stdcall; overload;
function MemoryResourceExists( var ResourceName : string ) : HRSRC;
{$ENDIF LOAD_FROM_RESOURCE}

{$IFDEF GetModuleHandle}
function MemoryGetModuleHandle( data: Pointer ): PMemoryModule; stdcall; {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}overload;{$IFEND}
{$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
function MemoryGetModuleHandle( FileName : string{$IFDEF LOAD_FROM_RESOURCE}; IsResource : boolean = False{$ENDIF} ): PMemoryModule; stdcall; overload;
{$IFEND}
{$ENDIF GetModuleHandle}

// return value is nil if function fails
function MemoryGetProcAddress( module: PMemoryModule; const name: PAnsiChar ): Pointer; stdcall;
// free module
procedure MemoryFreeLibrary( var module: PMemoryModule ); stdcall;

{$IFDEF MEMORY_DEPENDENCIES}
// Register a module name so that, when a memory/resource DLL imports it, the loader satisfies the
// import from this raw PE buffer (Data/Size) or from an RT_RCDATA/'DLL' resource (ResourceName)
// instead of loading it from disk. Registration order does not matter; nothing is loaded until an
// importing DLL actually needs the dependency. Names are matched case-insensitively, ignoring path
// and extension ("SDL3.dll" == "sdl3" == "SDL3").
procedure MemoryRegisterDllData( const ModuleName : string; Data : Pointer; Size : NativeUInt ); overload;
procedure MemoryRegisterDllData( const ModuleName, ResourceName : string ); overload;
procedure MemoryUnregisterDllData( const ModuleName : string );
{$ENDIF MEMORY_DEPENDENCIES}

{$IF Defined( MEMORY_SEH_X86 ) AND NOT Defined( CPUX64 )}
// True if ntdll's LdrpInvertedFunctionTable could be located on this OS, i.e. x86 SEH support for
// memory-loaded modules is active. False means the mechanism disabled itself (unknown OS layout).
function MemorySehX86Available : Boolean;
// Diagnostics: expose the located table and search it by image base ( -1 = not present ).
function MemorySehX86TableInfo( var Table : Pointer; var Count, MaxCount : DWORD ) : Boolean;
function MemorySehX86IndexOf( ImageBase : Pointer ) : Integer;
// Diagnostics: raw entry fields for a base ( RawExcDir = encoded SEH-table pointer as stored ).
function MemorySehX86EntryOf( ImageBase : Pointer; var RawExcDir : Pointer; var Count : DWORD ) : Integer;
// Exposed for out-of-band testing (e.g. registering a SEC_IMAGE-mapped module that never went
// through MemoryLoadLibrary at all): only module.codeBase and module.headers are read/written.
function RegisterInvertedFunctionTableEntry( module : PMemoryModule ) : Boolean;
procedure UnregisterInvertedFunctionTableEntry( module : PMemoryModule );
{$IFEND}

{$IFDEF REGISTER_IN_BASE_ADDRESS_INDEX}
// True if ntdll's LdrpModuleBaseAddressIndex red-black tree and the RtlRbInsertNodeEx /
// RtlRbRemoveNode helpers could be located, i.e. the base-address-index feature is active.
// False means the mechanism disabled itself (pre-Windows 8, unknown OS layout).
function MemoryBaseAddressIndexAvailable : Boolean;
{$ENDIF}

{$IF Defined( MEMORY_FROM_ADDRESS_X64 ) AND Defined( CPUX64 )}
// True if ntdll's LdrpInvertedFunctionTable could be located on this OS, i.e.
// GetModuleHandleEx(FROM_ADDRESS)/RtlPcToFileHeader support for memory-loaded x64 modules is active.
// False means the mechanism disabled itself (unknown OS layout).
function MemoryFromAddressX64Available : Boolean;
{$IFEND}

function CheckSumMappedFile( Module : PMemoryModule; HeaderSum : PCardinal; CheckSum : PCardinal ) : PIMAGE_NT_HEADERS32;

function MemoryEnumerateImports( data: Pointer; var Modules : string; DelimiterString : String = ';'; FullPath : Boolean = False ): ShortInt;  overload;
function MemoryEnumerateImports( ModuleData : Pointer; FileName : String; var Modules : String; DelimiterString : String = ';'; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255 ) : Int64; overload;
//{$IFDEF ALLOW_LOAD_FILES}
function MemoryEnumerateImportsFile( FileName : String; var Modules : String; DelimiterString : String = ';'; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : Int64; overload;
//{$ENDIF}
{$IFDEF LOAD_FROM_RESOURCE}
function MemoryEnumerateImports( ResourceName : string; FileName : String; var Modules : String; DelimiterString : String = ';'; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : Int64; overload;
{$ENDIF}

function MemoryEnumerateExports( ModuleData : Pointer; var AExports : String; DelimiterString : String = ';' ) : ShortInt; overload;
{$IFDEF ALLOW_LOAD_FILES}
function MemoryEnumerateExportsFile( FileName : String; var AExports : String; DelimiterString : String = ';'{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : ShortInt; overload;
{$ENDIF}
{$IFDEF LOAD_FROM_RESOURCE}
function MemoryEnumerateExports( ResourceName : string; var AExports : String; DelimiterString : String = ';'{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : ShortInt; overload;
{$ENDIF}

function ListMissingModules( ModuleData : Pointer; FileName : String; var Modules : String; DelimiterString : String = #13#10; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255 ) : Int64; overload;
{$IFDEF ALLOW_LOAD_FILES}
function ListMissingModulesFile( FileName : String; var Modules : String; DelimiterString : String = #13#10; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : Int64; overload;
{$ENDIF}
{$IFDEF LOAD_FROM_RESOURCE}
function ListMissingModules( ResourceName : string; FileName : String; var Modules : String; DelimiterString : String = #13#10; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : Int64; overload;
{$ENDIF}

implementation

uses
  {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
  ZLibMinimal,	
	{$IFDEF FastMM5}FastMM5{$ELSE}FastMM4{$ENDIF}	
  {$ELSE}
  ZLib
  {$IFEND}
  {$IFDEF lzma},LZMA, LZMA2{$ENDIF}
  {$IF ( Defined( GetModuleHandle ) AND Defined( GetModuleHandleCriticalSection ) )},SyncObjs{$IFEND}
  {$IFDEF USE_STREAMS},Classes, JclCompression{$ENDIF}
  ;

{$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
{The module bookkeeping (tModuleManager.fItems, the FileName strings and module.modules) must stay alive until after
FastMM's shutdown leak check, because the debug support DLL may still be needed to convert the stack traces of leaked
blocks to text (FastMM_FreeDebugSupportLibrary is called after the leak check).  Without countermeasures these blocks
are reported as (false positive) leaks, so - following the pattern of tModuleManager.Create, which already registers
the instance itself - they are registered as expected leaks and unregistered when they are actually freed.  FastMM
matches registered pointers against the block base as returned by GetMem, so for strings and dynamic arrays the RTL
header offset must be subtracted.}
function DynArrayBlockBase( ADynArray : Pointer ) : Pointer;
begin
  if NOT Assigned( ADynArray ) then
    result := nil
  else // TDynArrayRec: RefCnt + Length (+ padding under 64-bit)
    result := Pointer( PAnsiChar( ADynArray ) - {$IFDEF CPUX64}16{$ELSE}8{$ENDIF} );
end;

function StringBlockBase( AString : Pointer ) : Pointer;
begin
  if NOT Assigned( AString ) then
    result := nil
  else // StrRec: (CodePage + ElemSize +) RefCnt + Length (+ padding under 64-bit)
    result := Pointer( PAnsiChar( AString ) - {$IFDEF UNICODE}{$IFDEF CPUX64}16{$ELSE}12{$ENDIF}{$ELSE}8{$ENDIF} );
end;

procedure RegisterLeakBlock( ABlockBase : Pointer );
begin
  if NOT Assigned( ABlockBase ) then
    Exit;
  {$if Declared( FastMM_RegisterExpectedMemoryLeak )}
  FastMM_RegisterExpectedMemoryLeak( ABlockBase );
  {$ELSE}
  RegisterExpectedMemoryLeak( ABlockBase );
  {$IFEND}
end;

procedure UnregisterLeakBlock( ABlockBase : Pointer );
begin
  if NOT Assigned( ABlockBase ) then
    Exit;
  {$if Declared( FastMM_UnregisterExpectedMemoryLeak )}
  FastMM_UnregisterExpectedMemoryLeak( ABlockBase );
  {$ELSE}
  UnregisterExpectedMemoryLeak( ABlockBase );
  {$IFEND}
end;
{$IFEND Defined( FastMM4 ) OR Defined( FastMM5 )}

  { ++++++++++++++++++++++++++++++++++++++++
    ***  Missing Windows API Definitions ***
    ---------------------------------------- }
type
  {$IF CompilerVersion < 21}
  NativeUInt = Cardinal;
  NativeInt  = Integer;
  IntPtr     = NativeInt;  
  {$IFEND}

  {$IF NOT DECLARED(PULONGLONG)}
  PULONGLONG = ^UINT64;
  {$IFEND}

  {$IFDEF FastMM4} 
  PByte = System.PByte;
  {$ENDIF FastMM4}

  {$IF NOT DECLARED( IMAGE_BASE_RELOCATION )}
  {$ALIGN 4}
  IMAGE_BASE_RELOCATION = record
    VirtualAddress : Cardinal;
    SizeOfBlock    : Cardinal;
  end;
  {$ALIGN ON}
  PIMAGE_BASE_RELOCATION = ^IMAGE_BASE_RELOCATION;
  {$IFEND}

  // Types that are declared in Pascal-style ( ex.: PImageOptionalHeader ); redeclaring them in C-style
  {$IF NOT DECLARED( PIMAGE_DATA_DIRECTORY )}
  PIMAGE_DATA_DIRECTORY = ^IMAGE_DATA_DIRECTORY;
  {$IFEND}

  {$IF NOT DECLARED( PIMAGE_SECTION_HEADER )}
  PIMAGE_SECTION_HEADER = ^IMAGE_SECTION_HEADER;
  {$IFEND}

  {$IF NOT DECLARED( PIMAGE_EXPORT_DIRECTORY )}
  PIMAGE_EXPORT_DIRECTORY = ^IMAGE_EXPORT_DIRECTORY;
  {$IFEND}

  {$IF NOT DECLARED( PIMAGE_DOS_HEADER )}
  PIMAGE_DOS_HEADER = ^IMAGE_DOS_HEADER;
  {$IFEND}

  {$IF NOT DECLARED( PUINT_PTR )}
  PUINT_PTR = ^UINT_PTR;
  {$IFEND}

  {$IF NOT DECLARED( _IMAGE_TLS_DIRECTORY32 )}
  _IMAGE_TLS_DIRECTORY32 = record
    StartAddressOfRawData: Cardinal;
    EndAddressOfRawData: Cardinal;
    AddressOfIndex: Cardinal;             // PDWORD
    AddressOfCallBacks: Cardinal;         // PIMAGE_TLS_CALLBACK *
    SizeOfZeroFill: Cardinal;
    Characteristics: Cardinal;
  end;
  {$IFEND}

  {$IF NOT DECLARED( PIMAGE_TLS_DIRECTORY32 )}
  PIMAGE_TLS_DIRECTORY32 = ^_IMAGE_TLS_DIRECTORY32;
  {$IFEND}

  {$IF NOT DECLARED( _IMAGE_TLS_DIRECTORY64 )}
  _IMAGE_TLS_DIRECTORY64 = record
    StartAddressOfRawData: ULONGLONG;
    EndAddressOfRawData: ULONGLONG;
    AddressOfIndex: ULONGLONG;         // PDWORD
    AddressOfCallBacks: ULONGLONG;     // PIMAGE_TLS_CALLBACK *;
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;
  {$IFEND}

  {$IF NOT DECLARED( PIMAGE_TLS_DIRECTORY64 )}
  PIMAGE_TLS_DIRECTORY64 = ^_IMAGE_TLS_DIRECTORY64;
  {$IFEND}

// Things that are incorrectly defined at least up to XE6 (miss x64 mapping)
{$IFDEF CPUX64}
type
  PIMAGE_TLS_DIRECTORY = PIMAGE_TLS_DIRECTORY64;
const
  IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64;
type
{$ENDIF}

  {$IF NOT DECLARED( PIMAGE_TLS_CALLBACK )}
  PIMAGE_TLS_CALLBACK = procedure ( DllHandle: Pointer; Reason: Cardinal; Reserved: Pointer ) stdcall;
  {$IFEND}

  {$IF NOT DECLARED( _IMAGE_IMPORT_DESCRIPTOR )}
  _IMAGE_IMPORT_DESCRIPTOR = record
    case Byte of
      0: ( Characteristics: Cardinal );          // 0 for terminating null import descriptor
      1: ( OriginalFirstThunk: Cardinal;        // RVA to original unbound IAT ( PIMAGE_THUNK_DATA )
          TimeDateStamp: Cardinal;             // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ( new BIND )
                                            // O.W. date/time stamp of DLL bound to ( Old BIND )

          ForwarderChain: Cardinal;            // -1 if no forwarders
          Name: Cardinal;
          FirstThunk: Cardinal );                // RVA to IAT ( if bound this IAT has actual addresses )
  end;
  {$IFEND}

  {$IF NOT DECLARED( PIMAGE_IMPORT_DESCRIPTOR )}
  PIMAGE_IMPORT_DESCRIPTOR = ^_IMAGE_IMPORT_DESCRIPTOR;
  {$IFEND}

  {$IF NOT DECLARED( _IMAGE_IMPORT_BY_NAME )}
  _IMAGE_IMPORT_BY_NAME = record
    Hint: Word;
    Name: array[ 0..0 ] of Byte;
  end;
  {$IFEND}

  {$IF NOT DECLARED( PIMAGE_IMPORT_BY_NAME )}
  PIMAGE_IMPORT_BY_NAME = ^_IMAGE_IMPORT_BY_NAME;
  {$IFEND}

  {$IF NOT DECLARED( _IMAGE_IMPORT_DESCRIPTOR )}
  _IMAGE_IMPORT_DESCRIPTOR = record
    case Byte of
      0: ( Characteristics: Cardinal );          // 0 for terminating null import descriptor
      1: ( OriginalFirstThunk: Cardinal;        // RVA to original unbound IAT ( PIMAGE_THUNK_DATA )
          TimeDateStamp: Cardinal;             // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ( new BIND )
                                            // O.W. date/time stamp of DLL bound to ( Old BIND )

          ForwarderChain: Cardinal;            // -1 if no forwarders
          Name: Cardinal;
          FirstThunk: Cardinal );                // RVA to IAT ( if bound this IAT has actual addresses )
  end;
  {$IFEND}

  {$IF NOT DECLARED( IMAGE_IMPORT_DESCRIPTOR )}
  IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR;
  {$IFEND}

  {$IF NOT DECLARED( LPSYSTEM_INFO )}
  LPSYSTEM_INFO = ^SYSTEM_INFO;
  {$IFEND}

// Missing constants
const
  IMAGE_SIZEOF_BASE_RELOCATION = 8;
  IMAGE_REL_BASED_ABSOLUTE = 0;
  IMAGE_REL_BASED_HIGHLOW = 3;
  IMAGE_REL_BASED_DIR64 = 10;
{$IF NOT Defined( FPC ) AND ( CompilerVersion < 23 )}
  IMAGE_ORDINAL_FLAG64 = UInt64( $8000000000000000 );
  IMAGE_ORDINAL_FLAG32 = LongWord( $80000000 );
  IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32;
  HEAP_ZERO_MEMORY   = $00000008;
{$IFEND}

type
  TDllEntryProc = function( hinstDLL: HINST; fdwReason: Cardinal; lpReserved: Pointer ): BOOL; stdcall;

  TSectionFinalizeData = record
    address: Pointer;
    alignedAddress: Pointer;
    size: Cardinal;
    characteristics: Cardinal;
    last: Boolean;
  end;

// Explicitly export these functions to allow hooking of their origins
function GetProcAddress_Internal( hModule: HMODULE; lpProcName: LPCSTR ): FARPROC; stdcall; external kernel32 name 'GetProcAddress';
function LoadLibraryA_Internal( lpLibFileName: LPCSTR ): HMODULE; stdcall; external kernel32 name 'LoadLibraryA';
function FreeLibrary_Internal( hLibModule: HMODULE ): BOOL; stdcall; external kernel32 name 'FreeLibrary';

{$IF NOT Defined( FPC ) AND ( CompilerVersion < 23 )}
procedure GetNativeSystemInfo( lpSystemInfo: LPSYSTEM_INFO ); stdcall; external kernel32 name 'GetNativeSystemInfo';
{$IFEND}

{$IFDEF CPUX64}
// Unwind/exception support for memory-loaded x64 images. Without a registered .pdata table the OS
// cannot unwind through the module: SEH and Delphi exceptions raised inside it terminate the process
// (RtlpUnwindPrologue / "no unwind info"), and stack traces stop at the module boundary.
// These exports exist only in 64-bit kernel32, hence the CPUX64 guard.
{$IF NOT DECLARED( RtlAddFunctionTable )}
function RtlAddFunctionTable( FunctionTable : Pointer; EntryCount : DWORD; BaseAddress : UInt64 ) : ByteBool; stdcall; external kernel32 name 'RtlAddFunctionTable';
{$IFEND}
{$IF NOT DECLARED( RtlDeleteFunctionTable )}
function RtlDeleteFunctionTable( FunctionTable : Pointer ) : ByteBool; stdcall; external kernel32 name 'RtlDeleteFunctionTable';
{$IFEND}

type
  TMM_RUNTIME_FUNCTION = packed record
    BeginAddress      : DWORD;
    EndAddress        : DWORD;
    UnwindInfoAddress : DWORD;
  end;
{$ENDIF CPUX64}

{$IF NOT DECLARED( IsWow64Process )}
function IsWow64Process( hProcess : THandle; var Wow64Process : BOOL ) : BOOL; stdcall; external kernel32 name 'IsWow64Process';
{$IFEND}

{$IF NOT DECLARED( GetSystemWow64Directory )}
function GetSystemWow64Directory( lpBuffer : PChar; uSize : UINT ) : UINT; stdcall;
  external kernel32 name {$IFDEF UNICODE}'GetSystemWow64DirectoryW'{$ELSE}'GetSystemWow64DirectoryA'{$ENDIF};
{$IFEND}

// Copy from SysUtils to get rid of this unit
function StrComp( const Str1, Str2: PAnsiChar ): Integer;
var
  P1, P2: PAnsiChar;
begin
  P1 := Str1;
  P2 := Str2;
  while True do
    begin
    if ( P1^ <> P2^ ) or ( P1^ = #0 ) then
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      Exit( Ord( P1^ ) - Ord( P2^ ) );
      {$ELSE}
      begin
      result := Ord( P1^ ) - Ord( P2^ );
      Exit;
      end;
      {$IFEND}
    Inc( P1 );
    Inc( P2 );
    end;
end;

{$IFDEF MEMORY_DEPENDENCIES}
// Case-insensitive comparison of two module names, ignoring any path and file extension
// ( "SDL3.dll", "sdl3" and "C:\x\SDL3.DLL" all compare equal ).
function SameModuleName( const A, B : string ) : Boolean;
  function BaseName( const S : string ) : string;
  var
    i, dot : Integer;
  begin
    Result := S;
    for i := Length( Result ) downTo 1 do
      if ( Result[ i ] = '\' ) OR ( Result[ i ] = '/' ) OR ( Result[ i ] = ':' ) then
        begin
        Result := Copy( Result, i+1, Length( Result )-i );
        Break;
        end;
    dot := 0;
    for i := Length( Result ) downTo 1 do
      if ( Result[ i ] = '.' ) then
        begin
        dot := i;
        Break;
        end;
    if ( dot > 0 ) then
      Result := Copy( Result, 1, dot-1 );
  end;
var
  sa, sb : string;
begin
  sa := BaseName( A );
  sb := BaseName( B );
  Result := ( CompareString( LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar( sa ), Length( sa ), PChar( sb ), Length( sb ) ) = 2{CSTR_EQUAL} );
end;
{$ENDIF MEMORY_DEPENDENCIES}

{$IF NOT Declared( FileExists )}
function FileExists(const FileName: string): Boolean;
//function FileAge(const FileName: string): Integer;
type
  LongRec = packed record
    case Integer of
      0: (Lo, Hi: Word);
      1: (Words: array [0..1] of Word);
      2: (Bytes: array [0..3] of Byte);
  end;
var
  Handle: THandle;
  FindData: TWin32FindData;
  LocalFileTime: TFileTime;
  tmp : Integer;
begin
  Result := False;
  Handle := FindFirstFile(PChar(FileName), FindData);
  if Handle <> INVALID_HANDLE_VALUE then
  begin
    Windows.FindClose(Handle);
    if (FindData.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
    begin
      FileTimeToLocalFileTime(FindData.ftLastWriteTime, LocalFileTime);
      if FileTimeToDosDateTime(LocalFileTime, LongRec(tmp).Hi, LongRec(tmp).Lo) then
        begin
        result := True;
        Exit;
        end;
    end;
  end;
//  Result := -1;
//end;
//begin
//  Result := FileAge(FileName) <> -1;
end;
{$IFEND}

{$IF NOT Declared( ExceptionErrorMessage )}
type
  Exception = class(TObject)
  private
    Message: string;
  end;
function ExceptionErrorMessage(ExceptObject: TObject; ExceptAddr: Pointer; Buffer: PChar; Size: Integer): Integer;
{$IFDEF MSWINDOWS}
  function StrLCopy(Dest: PChar; const Source: PChar; MaxLen: Cardinal): PChar; overload;
  var
    Len: Cardinal;
  begin
    Result := Dest;
    Len := Length(Source);
    if Len > MaxLen then
      Len := MaxLen;
    Move(Source^, Dest^, Len * SizeOf(Char));
    Dest[Len] := #0;
  end;

  function StrScan(const Str: PChar; Chr: Char): PChar;
  begin
    Result := Str;
    while Result^ <> #0 do
    begin
      if Result^ = Chr then
        Exit;
      Inc(Result);
    end;
    if Chr <> #0 then
      Result := nil;
  end;

  function AnsiStrScan(Str: PChar; Chr: Char): PChar;
  begin
    Result := StrScan(Str, Chr);
(* Needs SysLocale // MS
    {$IFNDEF UNICODE}
    while Result <> nil do
    begin
  {$IFDEF MSWINDOWS}
      case StrByteType(Str, Integer(Result-Str)) of
        mbSingleByte: Exit;
        mbLeadByte: Inc(Result);
      end;
  {$ENDIF MSWINDOWS}
  {$IFDEF POSIX}
      if StrByteType(Str, Integer(Result-Str)) = mbSingleByte then
        Exit;
  {$ENDIF POSIX}
      Inc(Result);
      Result := StrScan(Result, Chr);
    end;
    {$ENDIF}
*)
  end;

  {$IFDEF UNICODE}
  function StrRScan(const Str: PWideChar; Chr: WideChar): PWideChar;
    function StrEnd(const Str: PWideChar): PWideChar;
    begin
      Result := Str;
      while Result^ <> #0 do
        Inc(Result);
    end;
  var
    MostRecentFound: PWideChar;
  begin
    if Chr = #0 then
      Result := StrEnd(Str)
    else
    begin
      Result := nil;

      MostRecentFound := Str;
      while True do
      begin
        while MostRecentFound^ <> Chr do
        begin
          if MostRecentFound^ = #0 then
            Exit;
          Inc(MostRecentFound);
        end;
        Result := MostRecentFound;
        Inc(MostRecentFound);
      end;
    end;
  end;
  {$ENDIF}

  function AnsiStrRScan(Str: PChar; Chr: Char): PChar;
  begin
    {$IFDEF UNICODE}
    result := StrRScan(Str, Chr);
    {$ELSE}
    Str := AnsiStrScan(Str, Chr);
    Result := Str;
    if Chr <> AnsiChar(#$0) then
    begin
      while Str <> nil do
      begin
        Result := Str;
        Inc(Str);
        Str := AnsiStrScan(Str, Chr);
      end;
    end
    {$ENDIF}
  end;

  function PointerToHex( P : Pointer; TypeSize : Byte; BigEndian : boolean = false ): string;
    function ByteToHex( B : Byte ) : String;
    const
      HexTable : Array[ 0..15 ] of Char = ( '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' );
    begin
      result := HexTable[ b div 16 ] + HexTable[ b mod 16 ];
    end;
  type
    TBytes = Array [ 0..15 ] of Byte;
    PBytes = ^TBytes;
  var
    Bytes : PBytes absolute P;
    i     : Integer;
  begin
    result := '';
    if ( P = nil ) then
      Exit;
    if ( TypeSize > SizeOf( TBytes ) ) then
      Exit;

    if BigEndian then
      begin
      for i := Low( Bytes^ ) To TypeSize-1 do
        result := result + ByteToHex( Bytes^[ i ] );
      end
    else
      begin
      for i := TypeSize-1 downTo Low( Bytes^ ) do
        result := result + ByteToHex( Bytes^[ i ] );
      end;

    i := Pos( ' ', Result );
    while ( i <> 0 ) do
      begin
      Result[ I ] := '0';
      i := Pos( ' ', Result );
      end;
  end;

  function ConvertAddr(Address: Pointer): Pointer;
  {$IFDEF Win64}
  begin
    Result := Address;
    if Result <> nil then
      Dec(PByte(Result), $1000);
  end;
  {$ELSE}
  asm //StackAlignSafe
          TEST    EAX,EAX         { Always convert nil to nil }
          JE      @@1
          SUB     EAX, $1000      { offset from code start; code start set by linker to $1000 }
  @@1:
  end;
  {$ENDIF Win64}
var
  MsgPtr: PChar;
  MsgEnd: PChar;
  MsgLen: Integer;
  ModuleName: array[0..MAX_PATH] of Char;
  Temp: array[0..MAX_PATH] of Char;
//  Format: array[0..255] of Char;
  Info: TMemoryBasicInformation;
  ConvertedAddress: Pointer;
  S : String;
begin
  VirtualQuery(ExceptAddr, Info, sizeof(Info));
  if (Info.State <> MEM_COMMIT) or
    (GetModuleFilename(THandle(Info.AllocationBase), Temp, SizeOf(Temp)) = 0) then
  begin
    GetModuleFileName(HInstance, Temp, SizeOf(Temp));
    ConvertedAddress := ConvertAddr(ExceptAddr);
  end
  else
    IntPtr(ConvertedAddress) := IntPtr(ExceptAddr) - IntPtr(Info.AllocationBase);
  StrLCopy( ModuleName, AnsiStrRScan(Temp, '\') + 1, SizeOf(ModuleName) - 1 );
  MsgPtr := '';
  MsgEnd := '';

  if Assigned( ExceptObject ) then // ExceptObject.ClassNameIs( 'Exception' ) then
  begin
    MsgPtr := PChar(Exception(ExceptObject).Message);
    MsgLen := Length(MsgPtr);
    if (MsgLen <> 0) and (MsgPtr[MsgLen - 1] <> '.') then
      MsgEnd := '.';
  end;
//  LoadString(FindResourceHInstance(HInstance),
//    PResStringRec(@SException).Identifier, Format, SizeOf(Format));

  S := 'Exception' + ' ' + ExceptObject.ClassName +' in Modul ' + ModuleName + ' bei ' + PointerToHex( @ConvertedAddress, SizeOf( ConvertedAddress ) ) + '.'+#13#10 + ' ' + MsgPtr + MsgEnd + #13#10;
  FillChar( Buffer[ 0 ], Size, 0 );
  Result := Length( S );
  Move( S[ 1 ], Buffer[ 0 ], Result );
end;
{$ENDIF}
{$IF defined(LINUX) or defined(MACOS) or defined(ANDROID)}
const
  UnknownModuleName = '<unknown>';
var
  MsgPtr: PChar;
  MsgEnd: PChar;
  MsgLen: Integer;
  Modulename: string;
  Info: dl_info;
begin
  MsgPtr := '';
  MsgEnd := '';
  if ExceptObject is Exception then
  begin
    MsgPtr := PChar(Exception(ExceptObject).Message);
    MsgLen := StrLen(MsgPtr);
    if (MsgLen <> 0) and (MsgPtr[MsgLen - 1] <> '.') then MsgEnd := '.';
  end;
  if (dladdr(IntPtr(ExceptAddr), Info) <> 0) and (Info.dli_fname <> nil) then
  begin
    ModuleName := string(Info.dli_fname);
    ModuleName := Modulename.SubString(Modulename.LastIndexOf( PathDelim) + 1)
  end
  else
  begin
    ModuleName := UnknownModuleName;
  end;
  StrLFmt(Buffer, Size, PChar(SException), [ExceptObject.ClassName, ModuleName,
    ExceptAddr, MsgPtr, MsgEnd]);
  Result := StrLen(Buffer);
end;
{$IFEND LINUX or MACOS or ANDROID}
{$IFEND}

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***                Missing WinAPI macros          ***
    ----------------------------------------------------- }

{$IF NOT DECLARED( IMAGE_ORDINAL )}
//  #define IMAGE_ORDINAL64( Ordinal ) ( Ordinal & 0xffff )
//  #define IMAGE_ORDINAL32( Ordinal ) ( Ordinal & 0xffff )
function IMAGE_ORDINAL( Ordinal: NativeUInt ): Word; {$IF Defined( FPC ) OR ( CompilerVersion >= 22 )}inline;{$IFEND}
begin
  Result := Ordinal and $FFFF;
end;
{$IFEND}

{$IF NOT DECLARED( IMAGE_SNAP_BY_ORDINAL )}
//  IMAGE_SNAP_BY_ORDINAL64( Ordinal ) ( ( Ordinal & IMAGE_ORDINAL_FLAG64 ) != 0 )
//  IMAGE_SNAP_BY_ORDINAL32( Ordinal ) ( ( Ordinal & IMAGE_ORDINAL_FLAG32 ) != 0 )
function IMAGE_SNAP_BY_ORDINAL32( Ordinal: NativeUInt ): Boolean; {$IF Defined( FPC ) OR ( CompilerVersion >= 22 )}inline;{$IFEND}
begin
  Result := ( ( Ordinal and IMAGE_ORDINAL_FLAG32 ) <> 0 );
end;

function IMAGE_SNAP_BY_ORDINAL64( Ordinal: NativeUInt ): Boolean; {$IF Defined( FPC ) OR ( CompilerVersion >= 22 )}inline;{$IFEND}
begin
  Result := ( ( Ordinal and IMAGE_ORDINAL_FLAG64 ) <> 0 );
end;
{$IFEND}

function GET_HEADER_DICTIONARY( module: PMemoryModule; idx: Integer ): PIMAGE_DATA_DIRECTORY;
begin
  if module^.headers.X64 then
    Result := PIMAGE_DATA_DIRECTORY( @( module.headers.headers64.OptionalHeader.DataDirectory[ idx ] ) )
  else
    Result := PIMAGE_DATA_DIRECTORY( @( module.headers.headers32.OptionalHeader.DataDirectory[ idx ] ) );
end;

function IMAGE_FIRST_SECTION( NtHeader: PIMAGE_NT_HEADERS32 ): PImageSectionHeader;
var
  OptionalHeaderAddr: PByte;
begin
  OptionalHeaderAddr := PByte( @NtHeader^.OptionalHeader );
  Inc( OptionalHeaderAddr, NtHeader^.FileHeader.SizeOfOptionalHeader );
  Result := PImageSectionHeader( OptionalHeaderAddr );
end;

function CopySections( data: Pointer; old_headers: PIMAGE_NT_HEADERS32; module: PMemoryModule ): Boolean;
var
  i, size: Integer;
  codebase: Pointer;
  dest: Pointer;
  section: PIMAGE_SECTION_HEADER;
begin
  codebase := module.codeBase;
  section := PIMAGE_SECTION_HEADER( IMAGE_FIRST_SECTION( module.headers.headers32 ) );
  for i := 0 to module.headers.headers32.FileHeader.NumberOfSections - 1 do
    begin
    // section doesn't contain data in the dll itself, but may define
    // uninitialized data
    if section.SizeOfRawData = 0 then
      begin
      if module.headers.X64 then
        size := PIMAGE_NT_HEADERS64( old_headers ).OptionalHeader.SectionAlignment
      else
        size := old_headers.OptionalHeader.SectionAlignment;
      if size > 0 then
        begin
        dest := VirtualAlloc( 
                             {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
                             PByte( codebase ) + section.VirtualAddress,
                             {$ELSE}
                             PAnsiChar( codebase ) + section.VirtualAddress,
                             {$IFEND}
                             size, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        if dest = nil then
          {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
          Exit( false );
          {$ELSE}
          begin
          result := false;
          Exit;
          end;
          {$IFEND}

        // Always use position from file to support alignments smaller
        // than page size.
        {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
        dest := PByte( codebase ) + section.VirtualAddress;
        {$ELSE}
        dest := PAnsiChar( codebase ) + section.VirtualAddress;
        {$IFEND}
        section.Misc.PhysicalAddress := Cardinal( dest );
        ZeroMemory( dest, size );
        end;
      // section is empty
      Inc( section );
      Continue;
      end;

    // commit memory block and copy data from dll
    dest := VirtualAlloc( 
                         {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
                         PByte( codebase ) + section.VirtualAddress,
                         {$ELSE}
                         PAnsiChar( codebase ) + section.VirtualAddress,
                         {$IFEND}
                         section.SizeOfRawData,
                         MEM_COMMIT,
                         PAGE_EXECUTE_READWRITE );
    if dest = nil then
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      Exit( false );
      {$ELSE}
      begin
      result := false;
      Exit;
      end;
      {$IFEND}

    // Always use position from file to support alignments smaller
    // than page size.
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    dest := PByte( codebase ) + section.VirtualAddress;
    CopyMemory( dest, PByte( data ) + section.PointerToRawData, section.SizeOfRawData );
    {$ELSE}
    dest := PAnsiChar( codebase ) + section.VirtualAddress;
    CopyMemory( dest, PAnsiChar( data ) + section.PointerToRawData, section.SizeOfRawData );
    {$IFEND}
    section.Misc.PhysicalAddress := Cardinal( dest );
    Inc(section); 
    end; // for

  Result := True;
end;

// Protection flags for memory pages ( Executable, Readable, Writeable )
const
  ProtectionFlags: array[ Boolean, Boolean, Boolean ] of Cardinal =
  ( 
    ( 
        // not executable
        ( PAGE_NOACCESS, PAGE_WRITECOPY ),
        ( PAGE_READONLY, PAGE_READWRITE )
    ),
    ( 
        // executable
        ( PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY ),
        ( PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE )
    )
 );

function FinalizeSection( module: PMemoryModule; const sectionData: TSectionFinalizeData ): Boolean;
var
  protect, oldProtect: Cardinal;
  executable, readable, writeable: Boolean;
begin
  if sectionData.size = 0 then
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit( True );
    {$ELSE}
    begin
    result := True;
    Exit;
    end;
    {$IFEND}

  if ( sectionData.characteristics and IMAGE_SCN_MEM_DISCARDABLE ) <> 0 then
    begin
    // section is not needed any more and can safely be freed
    if ( sectionData.address = sectionData.alignedAddress ) and
       ( sectionData.last or
       ( NOT module.headers.X64 AND ( module.headers.headers32.OptionalHeader.SectionAlignment = module.pageSize ) ) or
       ( module.headers.X64 AND ( module.headers.headers64.OptionalHeader.SectionAlignment = module.pageSize ) ) or
       ( sectionData.size mod module.pageSize = 0 ) ) then
         // Only allowed to decommit whole pages
         VirtualFree( sectionData.address, sectionData.size, MEM_DECOMMIT );
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit( True );
    {$ELSE}
    result := True;
    Exit;
    {$IFEND}
    end;

  // determine protection flags based on characteristics
  executable := ( sectionData.characteristics and IMAGE_SCN_MEM_EXECUTE ) <> 0;
  readable   := ( sectionData.characteristics and IMAGE_SCN_MEM_READ ) <> 0;
  writeable  := ( sectionData.characteristics and IMAGE_SCN_MEM_WRITE ) <> 0;
  protect := ProtectionFlags[ executable ][ readable ][ writeable ];
  if ( sectionData.characteristics and IMAGE_SCN_MEM_NOT_CACHED ) <> 0 then
    protect := protect or PAGE_NOCACHE;

  // change memory access flags
  Result := VirtualProtect( sectionData.address, sectionData.size, protect, oldProtect );
end;

function FinalizeSections( module: PMemoryModule ): Boolean;
  function GetRealSectionSize( module: PMemoryModule; section: PIMAGE_SECTION_HEADER ): Cardinal;
  begin
    Result := section.SizeOfRawData;
    if Result = 0 then
      if ( section.Characteristics and IMAGE_SCN_CNT_INITIALIZED_DATA ) <> 0 then
        begin
        if module.headers.X64 then
          Result := module.headers.headers64.OptionalHeader.SizeOfInitializedData
        else
          Result := module.headers.headers32.OptionalHeader.SizeOfInitializedData;
        end
      else if ( section.Characteristics and IMAGE_SCN_CNT_UNINITIALIZED_DATA ) <> 0 then
        begin
        if module.headers.X64 then
          Result := module.headers.headers64.OptionalHeader.SizeOfUninitializedData
        else
          Result := module.headers.headers32.OptionalHeader.SizeOfUninitializedData;
        end;
  end;
  function ALIGN_DOWN( address: Pointer; alignment: Cardinal ): Pointer;
  begin
    Result := Pointer( UINT_PTR( address ) and not ( alignment - 1 ) );
  end;

var
  i: Integer;
  section: PIMAGE_SECTION_HEADER;
  imageOffset: UINT_PTR;
  sectionData: TSectionFinalizeData;
  sectionAddress, alignedAddress: Pointer;
  sectionSize: Cardinal;
begin
  section := PIMAGE_SECTION_HEADER( IMAGE_FIRST_SECTION( module.headers.headers32 ) );
  if module.headers.X64 then
    imageOffset := ( NativeUInt( module.codeBase ) and $ffffffff00000000 )
  else
    imageOffset := 0;

//  {$IFDEF CPUX64}
//  imageOffset := ( NativeUInt( module.codeBase ) and $ffffffff00000000 );
//  {$ELSE}
//  imageOffset := 0;
//  {$ENDIF}

  sectionData.address := Pointer( UINT_PTR( section.Misc.PhysicalAddress ) or imageOffset );
  sectionData.alignedAddress := ALIGN_DOWN( sectionData.address, module.pageSize );
  sectionData.size := GetRealSectionSize( module, section );
  sectionData.characteristics := section.Characteristics;
  sectionData.last := False;
  Inc( section );

  // loop through all sections and change access flags
  for i := 1 to module.headers.headers32.FileHeader.NumberOfSections - 1 do
    begin
    sectionAddress := Pointer( UINT_PTR( section.Misc.PhysicalAddress ) or imageOffset );
    alignedAddress := ALIGN_DOWN( sectionData.address, module.pageSize );
    sectionSize := GetRealSectionSize( module, section );
    // Combine access flags of all sections that share a page
    // TODO( fancycode ): We currently share flags of a trailing large section
    //   with the page of a first small section. This should be optimized.
    if ( sectionData.alignedAddress = alignedAddress ) or
        {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
       ( PByte( sectionData.address ) + sectionData.size > PByte( alignedAddress ) ) then
        {$ELSE}
       ( PAnsiChar( sectionData.address ) + sectionData.size > PAnsiChar( alignedAddress ) ) then
        {$IFEND}
      begin
      // Section shares page with previous
      if ( section.Characteristics and IMAGE_SCN_MEM_DISCARDABLE = 0 ) or
         ( sectionData.Characteristics and IMAGE_SCN_MEM_DISCARDABLE = 0 ) then
        sectionData.characteristics := ( sectionData.characteristics or section.Characteristics ) and not IMAGE_SCN_MEM_DISCARDABLE
      else
        sectionData.characteristics := sectionData.characteristics or section.Characteristics;

      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      sectionData.size := PByte( sectionAddress ) + sectionSize - PByte( sectionData.address );
      {$ELSE}
      sectionData.size := PAnsiChar( sectionAddress ) + sectionSize - PAnsiChar( sectionData.address );
      {$IFEND}

      Inc( section );
      Continue;
      end;

    if not FinalizeSection( module, sectionData ) then
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      Exit( false );
      {$ELSE}
      begin
      result := false;
      Exit;
      end;
      {$IFEND}

    sectionData.address := sectionAddress;
    sectionData.alignedAddress := alignedAddress;
    sectionData.size := sectionSize;
    sectionData.characteristics := section.Characteristics;

    Inc( section );
    end; // for

  sectionData.last := True;
  if not FinalizeSection( module, sectionData ) then
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit( false );
    {$ELSE}
    begin
    result := false;
    Exit;
    end;
    {$IFEND}

  Result := True;
end;

{$IFDEF REGISTER_IN_PEB}
// --- Loader (PEB) registration -------------------------------------------------------------
// Layouts below are the stable prefix of the loader structures; every field used here has kept
// its offset from NT 4 through Windows 11. Records are deliberately NOT packed so Delphi applies
// the same natural alignment the OS uses (notably the 4 bytes of padding after SizeOfImage on x64).
type
  PMM_UNICODE_STRING = ^MM_UNICODE_STRING;
  MM_UNICODE_STRING = record
    Length        : Word;      // in BYTES, excluding the terminator
    MaximumLength : Word;      // in BYTES, including the terminator
    Buffer        : PWideChar;
  end;

  PMM_LIST_ENTRY = ^MM_LIST_ENTRY;
  MM_LIST_ENTRY = record
    Flink : PMM_LIST_ENTRY;
    Blink : PMM_LIST_ENTRY;
  end;

  PMM_PEB_LDR_DATA = ^MM_PEB_LDR_DATA;
  MM_PEB_LDR_DATA = record
    Length                          : Cardinal;
    Initialized                     : ByteBool;
    SsHandle                        : Pointer;
    InLoadOrderModuleList           : MM_LIST_ENTRY;
    InMemoryOrderModuleList         : MM_LIST_ENTRY;
    InInitializationOrderModuleList : MM_LIST_ENTRY;
  end;

  // RTL_BALANCED_NODE, as used by LdrpModuleBaseAddressIndex (Windows 8+).
  PMM_RB_NODE = ^MM_RB_NODE;
  MM_RB_NODE = record
    Left   : PMM_RB_NODE;
    Right  : PMM_RB_NODE;
    ParentValue : NativeUInt; // parent pointer with red/black bit in bit 0
  end;

  // RTL_RB_TREE header of ntdll's LdrpModuleBaseAddressIndex (Root + leftmost node).
  PMM_RB_TREE = ^TMM_RB_TREE;
  TMM_RB_TREE = record
    Root : PMM_RB_NODE;
    Min  : PMM_RB_NODE;
  end;

  PMM_LDR_DATA_TABLE_ENTRY = ^MM_LDR_DATA_TABLE_ENTRY;
  MM_LDR_DATA_TABLE_ENTRY = record
    InLoadOrderLinks           : MM_LIST_ENTRY;
    InMemoryOrderLinks         : MM_LIST_ENTRY;
    InInitializationOrderLinks : MM_LIST_ENTRY;
    DllBase                    : Pointer;
    EntryPoint                 : Pointer;
    SizeOfImage                : Cardinal;
    FullDllName                : MM_UNICODE_STRING;
    BaseDllName                : MM_UNICODE_STRING;
    Flags                      : Cardinal;
    LoadCount                  : Word;
    TlsIndex                   : Word;
    HashLinks                  : MM_LIST_ENTRY;
    TimeDateStamp              : Cardinal;
    // --- fields past here are version-dependent; we never rely on their fixed offset,
    //     BaseAddressIndexNode is located at runtime (see MM_FindBaseAddressIndexOffset). ---
  end;

  // Signature of the ntdll RB-tree helpers (undocumented but exported and stable).
  // Right is C's BOOLEAN (1 byte, exactly 0/1). A Delphi ByteBool/LongBool would encode
  // True as $FF/$FFFFFFFF and ntdll uses the value as a child-slot index -> corrupts the
  // tree and trips a FAST_FAIL consistency check (0xC0000409). Pass Byte(Ord(...)) only.
  TMM_RtlRbInsertNodeEx = procedure( Tree : Pointer; Parent : PMM_RB_NODE; Right : Byte; Node : PMM_RB_NODE ); stdcall;
  TMM_RtlRbRemoveNode   = procedure( Tree : Pointer; Node : PMM_RB_NODE ); stdcall;

const
  LDRP_IMAGE_DLL         = $00000004;
  LDRP_ENTRY_PROCESSED   = $00004000;
  LDRP_PROCESS_ATTACH_CALLED = $00080000;
  LDR_LOADCOUNT_PINNED   = $FFFF; // never unloaded by the loader

// PEB address: TEB is at GS:[$30] (x64) / FS:[$18] (x86); the PEB pointer sits inside it.
function MM_GetPEB : Pointer;
{$IFDEF CPUX64}
asm
  mov rax, gs:[$60]
end;
{$ELSE}
asm
  mov eax, fs:[$30]
end;
{$ENDIF}

function MM_GetLdr : PMM_PEB_LDR_DATA;
var
  peb : PByte;
begin
  Result := nil;
  peb := MM_GetPEB;
  if ( peb = nil ) then
    Exit;
  // PEB.Ldr: offset $18 on x64, $0C on x86
  Result := PMM_PEB_LDR_DATA( PPointer( peb + {$IFDEF CPUX64}$18{$ELSE}$0C{$ENDIF} )^ );
end;

{$IFDEF REGISTER_IN_BASE_ADDRESS_INDEX}
// =================================================================================================
//  Base address index - ntdll!LdrpModuleBaseAddressIndex
//  Faithful port of MemoryModulePP ( bb107 ): BaseAddressIndex.cpp + the locator from
//  Initialize.cpp::FindLdrpModuleBaseAddressIndex. Since Windows 8 the loader resolves
//  address->module (LdrpFindLoadedDllByAddress, used by GetModuleHandleEx(FROM_ADDRESS),
//  GetModuleFileName and RtlIsValidHandler) through this red-black tree instead of the PEB lists.
//  Inserting our module's BaseAddressIndexNode makes the OS attribute addresses inside the image
//  to the module - the piece that REGISTER_IN_PEB alone cannot provide.
//  Everything is best-effort and only active on Windows 8+. If the tree or the ntdll helpers cannot
//  be located the feature silently disables itself and load still succeeds. Manipulating the tree
//  races with the loader when other threads load/unload DLLs; the original C++ accepts this.
// =================================================================================================

// ntdll imports (RtlGetNtVersionNumbers cannot be spoofed by app-compat GetVersionEx lies).
function MM_RtlGetNtVersionNumbers( var Major, Minor, Build : DWORD ) : DWORD; stdcall; external 'ntdll.dll' name 'RtlGetNtVersionNumbers';
function MM_RtlImageNtHeader( Base : Pointer ) : PIMAGE_NT_HEADERS32; stdcall; external 'ntdll.dll' name 'RtlImageNtHeader';

const
  // Field offsets inside the Win8+ LDR_DATA_TABLE_ENTRY. The prefix layout is identical on every
  // Windows 8/8.1/10/11 build, so these are stable (they match LDR_DATA_TABLE_ENTRY_WIN8/WIN10).
  MM_DDAG_NODE_OFFSET          = {$IFDEF CPUX64}$98{$ELSE}$50{$ENDIF};
  MM_BASE_ADDRESS_INDEX_OFFSET = {$IFDEF CPUX64}$C8{$ELSE}$68{$ENDIF};
  MM_REFERENCE_COUNT_OFFSET    = {$IFDEF CPUX64}$114{$ELSE}$9C{$ENDIF};
  MM_DDAG_LOADCOUNT_OFFSET     = {$IFDEF CPUX64}$18{$ELSE}$0C{$ENDIF};
  // DdagNode layout: Modules list at +0, LoadCount at +$0C/$18, State at +$20/$38
  // (matches LDR_DDAG_NODE; ntdll reads State through [Ddag+$20] on x86).
  MM_DDAG_MODULES_OFFSET       = 0;
  MM_DDAG_STATE_OFFSET         = {$IFDEF CPUX64}$38{$ELSE}$20{$ENDIF};
  MM_DDAG_NODE_SIZE            = $50;  // enough for both x86 (0x30) and x64 (0x4C)
  MM_NODE_MODULE_LINK_OFFSET   = {$IFDEF CPUX64}$A0{$ELSE}$54{$ENDIF};
  // Fake LDR entry allocation: must cover the RB node (+$68/$C8 .. +0xC) AND the loader-touched
  // fields up to ReferenceCount (+$9C/$114) - ntdll's LdrpFindLoadedDllByAddress does
  // "lock incl [entry+RefCount]".
  MM_FAKE_ENTRY_SIZE           = $140;
  // ParentValue stores the parent pointer in the high bits; low 3 bits carry red/balance state.
  MM_RB_PARENT_MASK            = {$IFDEF CPUX64}$FFFFFFFFFFFFFFF8{$ELSE}$FFFFFFF8{$ENDIF};

var
  MM_BaseAddressIndexTree  : PMM_RB_TREE = nil;          // located ntdll!LdrpModuleBaseAddressIndex
  MM_RbInsertNodeExFn      : TMM_RtlRbInsertNodeEx = nil;
  MM_RbRemoveNodeFn        : TMM_RtlRbRemoveNode = nil;
  MM_BaseAddressIndexTried : Boolean = False;
  MM_IsWin10Plus           : Boolean = False;

function MM_MemCompare( P1, P2 : Pointer; Len : NativeUInt ) : Boolean;
var
  a, b : PByte;
begin
  a := P1;
  b := P2;
  while ( Len > 0 ) do
    begin
    if ( a^ <> b^ ) then
      begin
      Result := False;
      Exit;
      end;
    Inc( a );
    Inc( b );
    Dec( Len );
    end;
  Result := True;
end;

function MM_SectionNameIs( sect : PImageSectionHeader; const Name : AnsiString ) : Boolean;
var
  i    : Integer;
  a, b : Byte;
begin
  Result := False;
  for i := 0 to 7 do
    begin
    a := sect.Name[ i ];
    if ( i < Length( Name ) ) then b := Byte( Name[ i+1 ] ) else b := 0;
    if ( a >= Ord( 'A' ) ) AND ( a <= Ord( 'Z' ) ) then Inc( a, 32 );
    if ( b >= Ord( 'A' ) ) AND ( b <= Ord( 'Z' ) ) then Inc( b, 32 );
    if ( a <> b ) then
      Exit;
    end;
  Result := True;
end;

// Linear scan of one section of a mapped image for a byte pattern, starting at FromAddress
// (nil = start of the section). Returns the absolute address of the first match or nil.
// Port of the pattern-search part of Utils.cpp::RtlFindMemoryBlockFromModuleSection.
function MM_ScanSectionPattern( ModuleHandle : Pointer; const SectionName : AnsiString;
  Pattern : Pointer; PatternSize : NativeUInt; FromAddress : PByte ) : PByte;
var
  nt    : PIMAGE_NT_HEADERS32;
  sect  : PImageSectionHeader;
  base  : PByte;
  e, p  : PByte;
  vsize : NativeUInt;
  i     : Integer;
begin
  Result := nil;
  nt := MM_RtlImageNtHeader( ModuleHandle );
  if ( nt = nil ) then
    Exit;
  sect  := IMAGE_FIRST_SECTION( nt );
  base  := nil;
  vsize := 0;
  for i := 0 to nt.FileHeader.NumberOfSections - 1 do
    begin
    if MM_SectionNameIs( sect, SectionName ) then
      begin
      base  := PByte( NativeUInt( ModuleHandle ) + sect.VirtualAddress );
      vsize := sect.Misc.VirtualSize;
      Break;
      end;
    Inc( sect );
    end;
  if ( base = nil ) OR ( vsize < PatternSize ) then
    Exit;
  {$IFDEF DEBUG_RB}
  WriteLn( 'DBG scan: section "', SectionName, '" base=', UInt64( NativeUInt( base ) ), ' vsize=', UInt64( vsize ) );
  {$ENDIF}
  e := base + vsize - PatternSize;
  if ( FromAddress = nil ) OR ( NativeUInt( FromAddress ) < NativeUInt( base ) ) then
    p := base
  else if ( NativeUInt( FromAddress ) > NativeUInt( e ) ) then
    Exit
  else
    p := FromAddress;
  while ( NativeUInt( p ) <= NativeUInt( e ) ) do
    begin
    if MM_MemCompare( Pattern, p, PatternSize ) then
      begin
      Result := p;
      Exit;
      end;
    Inc( p );
    end;
end;

// Same as MM_ScanSectionPattern, but Mask[ i ] = 0 marks Pattern[ i ] as "don't care" (any byte
// matches) - an AOB/wildcard scan, for locating code whose opcodes are stable across builds but
// whose operands (absolute addresses, call/jmp rel32 targets, stack displacements) are not.
function MM_ScanSectionPatternMasked( ModuleHandle : Pointer; const SectionName : AnsiString;
  Pattern, Mask : Pointer; PatternSize : NativeUInt; FromAddress : PByte ) : PByte;
var
  nt    : PIMAGE_NT_HEADERS32;
  sect  : PImageSectionHeader;
  base  : PByte;
  e, p  : PByte;
  vsize : NativeUInt;
  i     : Integer;
  pat, msk, cand : PByte;
  hit   : Boolean;
begin
  Result := nil;
  nt := MM_RtlImageNtHeader( ModuleHandle );
  if ( nt = nil ) then
    Exit;
  sect  := IMAGE_FIRST_SECTION( nt );
  base  := nil;
  vsize := 0;
  for i := 0 to nt.FileHeader.NumberOfSections - 1 do
    begin
    if MM_SectionNameIs( sect, SectionName ) then
      begin
      base  := PByte( NativeUInt( ModuleHandle ) + sect.VirtualAddress );
      vsize := sect.Misc.VirtualSize;
      Break;
      end;
    Inc( sect );
    end;
  if ( base = nil ) OR ( vsize < PatternSize ) then
    Exit;
  e := base + vsize - PatternSize;
  if ( FromAddress = nil ) OR ( NativeUInt( FromAddress ) < NativeUInt( base ) ) then
    p := base
  else if ( NativeUInt( FromAddress ) > NativeUInt( e ) ) then
    Exit
  else
    p := FromAddress;
  while ( NativeUInt( p ) <= NativeUInt( e ) ) do
    begin
    hit  := True;
    pat  := Pattern;
    msk  := Mask;
    cand := p;
    for i := 0 to PatternSize - 1 do
      begin
      if ( msk^ <> 0 ) AND ( pat^ <> cand^ ) then
        begin
        hit := False;
        Break;
        end;
      Inc( pat );
      Inc( msk );
      Inc( cand );
      end;
    if hit then
      begin
      Result := p;
      Exit;
      end;
    Inc( p );
    end;
end;

// Finds ntdll's own LDR_DATA_TABLE_ENTRY by walking the PEB InMemoryOrderModuleList.
function MM_FindNtdllLdrEntry : PMM_LDR_DATA_TABLE_ENTRY;
var
  ldr    : PMM_PEB_LDR_DATA;
  head   : PMM_LIST_ENTRY;
  cur    : PMM_LIST_ENTRY;
  entry  : PMM_LDR_DATA_TABLE_ENTRY;
  hNtdll : Pointer;
begin
  Result := nil;
  ldr := MM_GetLdr;
  if ( ldr = nil ) then
    Exit;
  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if ( hNtdll = nil ) then
    Exit;
  head := @ldr.InMemoryOrderModuleList;
  cur  := head.Flink;
  while ( cur <> head ) do
    begin
    entry := PMM_LDR_DATA_TABLE_ENTRY( PByte( cur ) - SizeOf( MM_LIST_ENTRY ) );
    if ( entry.DllBase = hNtdll ) then
      begin
      Result := entry;
      Exit;
      end;
    cur := cur.Flink;
    end;
end;

// Locates ntdll's LdrpModuleBaseAddressIndex (an RTL_RB_TREE) by walking up the parent chain from
// the ntdll entry's BaseAddressIndexNode to the tree root, then pattern-scanning ntdll's .data for
// a storage cell that holds exactly that root pointer - the tree header's Root field (Min normally
// differs, so the value occurs exactly once). Returns nil if anything looks wrong.
function MM_FindLdrpModuleBaseAddressIndex : PMM_RB_TREE;
var
  hNtdll : Pointer;
  nt10   : PMM_LDR_DATA_TABLE_ENTRY;
  node   : PMM_RB_NODE;
  rootAddr : Pointer;
  hit1, hit2 : PByte;
  vMajor, vMinor, vBuild : DWORD;
begin
  Result := nil;
  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if ( hNtdll = nil ) then
    Exit;
  nt10 := MM_FindNtdllLdrEntry;
  if ( nt10 = nil ) then
    Exit;

  MM_RtlGetNtVersionNumbers( vMajor, vMinor, vBuild );
  if ( vMajor < 6 ) OR ( ( vMajor = 6 ) AND ( vMinor < 2 ) ) then
    Exit; // LdrpModuleBaseAddressIndex exists since Windows 8 only

  node := PMM_RB_NODE( PByte( nt10 ) + MM_BASE_ADDRESS_INDEX_OFFSET );
  while ( ( node.ParentValue AND MM_RB_PARENT_MASK ) <> 0 ) do
    node := PMM_RB_NODE( node.ParentValue AND MM_RB_PARENT_MASK );

  if ( ( node.ParentValue AND 1 ) <> 0 ) then
    Exit; // a valid tree root is black

  rootAddr := node;
  hit1 := MM_ScanSectionPattern( hNtdll, '.data', @rootAddr, SizeOf( Pointer ), nil );
  {$IFDEF DEBUG_RB}
  WriteLn( 'DBG loc: ntdll=', UInt64( NativeUInt( hNtdll ) ), ' node(root)=', UInt64( NativeUInt( node ) ), ' hit1=', UInt64( NativeUInt( hit1 ) ) );
  {$ENDIF}
  if ( hit1 <> nil ) then
    begin
    hit2 := MM_ScanSectionPattern( hNtdll, '.data', @rootAddr, SizeOf( Pointer ), hit1 + 1 );
    {$IFDEF DEBUG_RB}
    WriteLn( 'DBG loc: hit2=', UInt64( NativeUInt( hit2 ) ) );
    {$ENDIF}
    if ( hit2 = nil ) then
      begin
      Result := PMM_RB_TREE( hit1 );
      {$IFDEF DEBUG_RB}
      WriteLn( 'DBG loc: TREE@', UInt64( NativeUInt( Result ) ), ' Root=', UInt64( NativeUInt( Result.Root ) ), ' Min=', UInt64( NativeUInt( Result.Min ) ) );
      {$ENDIF}
      if ( Result.Root = nil ) OR ( Result.Min = nil ) then
        Result := nil;
      end;
    end;
end;

// One-time lazy setup: caches the version check, the ntdll RB helpers and the tree location.
// A benign race between threads re-running the locator is accepted (both write the same values).
procedure MM_EnsureBaseAddressIndex;
var
  vMajor, vMinor, vBuild : DWORD;
  hNtdll : Pointer;
begin
  if MM_BaseAddressIndexTried then
    Exit;
  MM_BaseAddressIndexTried := True;

  MM_RtlGetNtVersionNumbers( vMajor, vMinor, vBuild );
  MM_IsWin10Plus := ( vMajor > 10 ) OR ( vMajor = 10 );

  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if ( hNtdll <> nil ) then
    begin
    MM_RbInsertNodeExFn := TMM_RtlRbInsertNodeEx( GetProcAddress( HMODULE( hNtdll ), 'RtlRbInsertNodeEx' ) );
    MM_RbRemoveNodeFn   := TMM_RtlRbRemoveNode( GetProcAddress( HMODULE( hNtdll ), 'RtlRbRemoveNode' ) );
    end;

  MM_BaseAddressIndexTree := MM_FindLdrpModuleBaseAddressIndex;
end;

// Wrapper matching BaseAddressIndex.cpp: zero the node, then let ntdll insert it into the tree.
procedure MM_DoRbInsertNodeEx( Tree : PMM_RB_TREE; Parent, Node : PMM_RB_NODE; Right : Boolean );
begin
  ZeroMemory( Node, SizeOf( MM_RB_NODE ) );
  if Assigned( MM_RbInsertNodeExFn ) then
    MM_RbInsertNodeExFn( Tree, Parent, Byte( Ord( Right ) ), Node );
end;

// Port of BaseAddressIndex.cpp::RtlInsertModuleBaseAddressIndexNode. Walks the tree to find the
// insertion parent, or bumps the reference counts when the base address is already present.
function MM_InsertModuleBaseAddressIndexNode( DataTableEntry : PMM_LDR_DATA_TABLE_ENTRY; BaseAddress : Pointer ) : Boolean;
var
  tree    : PMM_RB_TREE;
  ldrNode : PMM_LDR_DATA_TABLE_ENTRY;
  rbNode  : PMM_RB_NODE;
  bRight  : Boolean;
  ddag    : Pointer;
begin
  Result := False;
  tree := MM_BaseAddressIndexTree;
  if ( tree = nil ) OR ( tree.Root = nil ) then
    begin
    {$IFDEF DEBUG_RB}
    WriteLn( 'DBG ins: tree nil or root nil, base=', UInt64( NativeUInt( BaseAddress ) ) );
    {$ENDIF}
    Exit;
    end;

  ldrNode := PMM_LDR_DATA_TABLE_ENTRY( PByte( tree.Root ) - MM_BASE_ADDRESS_INDEX_OFFSET );
  bRight  := False;
  {$IFDEF DEBUG_RB}
  WriteLn( 'DBG ins: base=', UInt64( NativeUInt( BaseAddress ) ), ' rootnode=', UInt64( NativeUInt( tree.Root ) ), ' rootentry=', UInt64( NativeUInt( ldrNode ) ), ' rootDllBase=', UInt64( NativeUInt( ldrNode.DllBase ) ) );
  {$ENDIF}
  while True do
    begin
    if ( NativeUInt( BaseAddress ) < NativeUInt( ldrNode.DllBase ) ) then
      begin
      rbNode := PMM_RB_NODE( PByte( ldrNode ) + MM_BASE_ADDRESS_INDEX_OFFSET ).Left;
      if ( rbNode = nil ) then
        Break;
      ldrNode := PMM_LDR_DATA_TABLE_ENTRY( PByte( rbNode ) - MM_BASE_ADDRESS_INDEX_OFFSET );
      end
    else if ( NativeUInt( BaseAddress ) > NativeUInt( ldrNode.DllBase ) ) then
      begin
      rbNode := PMM_RB_NODE( PByte( ldrNode ) + MM_BASE_ADDRESS_INDEX_OFFSET ).Right;
      if ( rbNode = nil ) then
        begin
        bRight := True;
        Break;
        end;
      ldrNode := PMM_LDR_DATA_TABLE_ENTRY( PByte( rbNode ) - MM_BASE_ADDRESS_INDEX_OFFSET );
      end
    else
      begin
      // base address already in the tree: bump the loader reference counts, nothing inserted
      ddag := PPointer( PByte( ldrNode ) + MM_DDAG_NODE_OFFSET )^;
      if ( ddag <> nil ) then
        Inc( PDWORD( PByte( ddag ) + MM_DDAG_LOADCOUNT_OFFSET )^ );
      if MM_IsWin10Plus then
        Inc( PDWORD( PByte( ldrNode ) + MM_REFERENCE_COUNT_OFFSET )^ );
      Result := True;
      Exit;
      end;
    end;

  MM_DoRbInsertNodeEx( tree,
                       PMM_RB_NODE( PByte( ldrNode ) + MM_BASE_ADDRESS_INDEX_OFFSET ),
                       PMM_RB_NODE( PByte( DataTableEntry ) + MM_BASE_ADDRESS_INDEX_OFFSET ),
                       bRight );
  {$IFDEF DEBUG_RB}
  WriteLn( 'DBG ins: inserted under ldrNode=', UInt64( NativeUInt( ldrNode ) ), ' base=', UInt64( NativeUInt( ldrNode.DllBase ) ), ' bRight=', UInt64( NativeUInt( Integer( bRight ) ) ) );
  {$ENDIF}
  Result := True;
end;

// Port of BaseAddressIndex.cpp::RtlRemoveModuleBaseAddressIndexNode.
procedure MM_RemoveModuleBaseAddressIndexNode( DataTableEntry : PMM_LDR_DATA_TABLE_ENTRY );
begin
  if Assigned( MM_RbRemoveNodeFn ) AND ( MM_BaseAddressIndexTree <> nil ) then
    MM_RbRemoveNodeFn( MM_BaseAddressIndexTree,
                       PMM_RB_NODE( PByte( DataTableEntry ) + MM_BASE_ADDRESS_INDEX_OFFSET ) );
end;

// Gives a fake LDR entry a valid Win8+ DdagNode. ntdll's LdrpFindLoadedDllByAddress (and its
// inline copy in the load path) walks LdrpModuleBaseAddressIndex and, once it attributes an address
// inside our image to the module, dereferences entry->DdagNode for its refcount bookkeeping:
//   eax = entry->DdagNode; if (Ddag->LoadCount != -1) { first = Ddag->Modules.Flink;
//   if (!(first->Flags & 0x20)) entry->ReferenceCount++; }  out = Ddag->State;
// A NULL DdagNode makes that crash (0xC0000005, cmpl $ffffffff,0xc(%eax)). Mirrors
// LdrEntry.cpp::RtlInitializeLdrDataTableEntry: self-links DdagNode->Modules <-> entry->
// NodeModuleLink and sets LoadCount/State/ReferenceCount. Allocated on the process heap, freed by
// MM_UnregisterFakeDdagNode.
function MM_InitFakeLdrDdagNode( entry : PMM_LDR_DATA_TABLE_ENTRY ) : Boolean;
var
  ddag   : PByte;
  dMods  : PMM_LIST_ENTRY;
  nMod   : PMM_LIST_ENTRY;
begin
  Result := False;
  ddag := HeapAlloc( GetProcessHeap, HEAP_ZERO_MEMORY, MM_DDAG_NODE_SIZE );
  if ( ddag = nil ) then
    Exit;
  dMods := PMM_LIST_ENTRY( ddag + MM_DDAG_MODULES_OFFSET );
  nMod  := PMM_LIST_ENTRY( PByte( entry ) + MM_NODE_MODULE_LINK_OFFSET );
  nMod.Flink  := Pointer( dMods );
  nMod.Blink  := Pointer( dMods );
  dMods.Flink := Pointer( nMod );
  dMods.Blink := Pointer( nMod );
  PDWORD( ddag + MM_DDAG_LOADCOUNT_OFFSET )^ := 1;          // never -1 (skip-refcount sentinel)
  PDWORD( ddag + MM_DDAG_STATE_OFFSET )^     := 9;          // LdrModulesReadyToRun
  PPointer( PByte( entry ) + MM_DDAG_NODE_OFFSET )^ := ddag;
  PDWORD( PByte( entry ) + MM_REFERENCE_COUNT_OFFSET )^ := 1; // Win10+
  Result := True;
end;

procedure MM_UnregisterFakeDdagNode( entry : PMM_LDR_DATA_TABLE_ENTRY );
begin
  if ( PPointer( PByte( entry ) + MM_DDAG_NODE_OFFSET )^ <> nil ) then
    begin
    HeapFree( GetProcessHeap, 0, PPointer( PByte( entry ) + MM_DDAG_NODE_OFFSET )^ );
    PPointer( PByte( entry ) + MM_DDAG_NODE_OFFSET )^ := nil;
    end;
end;

function MemoryBaseAddressIndexAvailable : Boolean;
begin
  MM_EnsureBaseAddressIndex;
  Result := ( MM_BaseAddressIndexTree <> nil ) AND Assigned( MM_RbInsertNodeExFn ) AND Assigned( MM_RbRemoveNodeFn );
end;
{$ENDIF REGISTER_IN_BASE_ADDRESS_INDEX}

{$IFDEF MEMORY_HANDLE_TLS}
// =================================================================================================
//  Dynamic TLS data - ntdll!LdrpHandleTlsData / LdrpReleaseTlsEntry (LdrpTls path)
//  Faithful port of MemoryModulePP ( bb107 ): MmpLdrpTls.cpp. Calling the loader's internal
//  LdrpHandleTlsData with our fake LDR entry makes the loader set up the module's TLS template
//  and give it a real TLS index (Entry->TlsIndex). Without this, threadvar/__declspec(thread)
//  inside a memory-loaded DLL reads garbage: RegisterInPEB gives us a list entry and
//  REGISTER_IN_BASE_ADDRESS_INDEX an address->module attribution, but neither allocates the
//  per-thread TLS storage that the compiler-generated threadvar code expects.
//  LdrpReleaseTlsEntry undoes that on unload (before the fake LDR entry is freed).
//  Scope: x64 uses MmpLdrpTls.cpp's original string+C_SCOPE_TABLE locator, Windows 10.0+ only
//  (the Win7/8/8.1 LdrpHandleTlsData patterns are useless without a matching release routine).
//  x86 (incl. WOW64) ports the same two-routine mechanism via its own AOB/wildcard locator
//  (MM_FindLdrpHandleTlsData10 / MM_FindLdrpReleaseTlsEntry further down, {$IFNDEF CPUX64}
//  branch) - measured on two Windows 11 24H2 builds, not yet confirmed on Windows 10 (the real
//  field target - see TODO.md's SignoTec STPadLib entry).
//  Best-effort either way: if the routines cannot be located the feature silently disables itself
//  and load still succeeds (only the TLS data is then missing - callbacks still run via ExecuteTLS).
//  Convention: on Win8.1+ the loader uses a register-based ("thiscall-shaped") convention for both
//  routines - on x64 this is identical to stdcall (first arg in RCX), so the stdcall declarations
//  below are used directly there; on x86 it is NOT plain stdcall despite the PDB's "@N"-decorated
//  names - Entry arrives in ECX (/Opt in EDX for LdrpReleaseTlsEntry), confirmed by live
//  disassembly, so x86 calls go through the MM_CallLdrp*_X86 thunks instead (see their own
//  comments, next to the x86 locators).
// =================================================================================================

{$IFDEF CPUX64}
type
  TMM_LdrpHandleTlsDataFn   = function( Entry : PMM_LDR_DATA_TABLE_ENTRY ) : LongWord; stdcall;
  TMM_LdrpReleaseTlsEntryFn = function( Entry : PMM_LDR_DATA_TABLE_ENTRY; Opt : Pointer ) : LongWord; stdcall;
{$ENDIF}

var
  // x64: typed stdcall pointers, called directly (first arg in RCX is identical under both
  // conventions there). x86: plain Pointer, called ONLY through the MM_CallLdrp*_X86 thunks
  // below - the real convention passes Entry in ECX (/Opt in EDX), confirmed by live
  // disassembly, NOT on the stack as a naive stdcall/register declaration would assume.
  MM_LdrpHandleTlsDataFn   : {$IFDEF CPUX64}TMM_LdrpHandleTlsDataFn{$ELSE}Pointer{$ENDIF} = nil;
  MM_LdrpReleaseTlsEntryFn : {$IFDEF CPUX64}TMM_LdrpReleaseTlsEntryFn{$ELSE}Pointer{$ENDIF} = nil;
  MM_LdrpTlsInitialized    : Boolean = False;

const
  MM_TLS_STATUS_SUCCESS       = 0;
  MM_TLS_STATUS_NOT_SUPPORTED = $C00000BB;

// Locates ntdll!LdrpHandleTlsData on Windows 10+ x64 (the only combination LdrpTls supports).
// Port of MmpLdrpTls.cpp::RtlFindLdrpHandleTlsData10: finds the "LdrpHandleTlsData" string
// literal in .rdata, then the "lea rdx,[rip+off]" instruction in .text that references it,
// then the C_SCOPE_TABLE and walks back to the function's 4-byte 0xCC padding.
function MM_FindLdrpHandleTlsData10 : Pointer;
{$IFDEF CPUX64}
var
  hNtdll          : Pointer;
  strHit, p       : PByte;
  insOff          : DWORD;
  exceptionBlock  : PByte;
  ebAddr          : DWORD;
  ebBytes         : array[ 0..3 ] of Byte;
  scopeHit        : PByte;
  block           : PByte;
  blockBackup     : PByte;
  leaPat          : array[ 0..2 ] of Byte;
begin
  Result := nil;
  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if ( hNtdll = nil ) then
    Exit;

  // 1) the "LdrpHandleTlsData\0" string literal in .rdata
  strHit := MM_ScanSectionPattern( hNtdll, '.rdata', PAnsiChar( 'LdrpHandleTlsData'#0 ), 18, nil );
  if ( strHit = nil ) then
    Exit;

  // 2) "lea rdx,[rip+0x????]" in .text; the rip-relative offset must point at the string literal
  leaPat[ 0 ] := $48; leaPat[ 1 ] := $8D; leaPat[ 2 ] := $15;
  exceptionBlock := nil;
  p := nil;
  while True do
    begin
    p := MM_ScanSectionPattern( hNtdll, '.text', @leaPat, 3, p );
    if ( p = nil ) then
      Exit; // no more hits: not found
    insOff := PDWORD( p + 3 )^;
    if ( NativeUInt( strHit ) = NativeUInt( p ) + insOff + 7 ) then
      begin
      exceptionBlock := p;
      Break;
      end;
    Inc( p ); // try the next occurrence
    end;

  // 3) walk back to the exception block header (a 0xCC byte), at most 0x50 bytes
  while ( exceptionBlock^ <> $CC ) do
    begin
    if ( NativeUInt( p ) - NativeUInt( exceptionBlock ) > $50 ) then
      Exit;
    Dec( exceptionBlock );
    end;
  Inc( exceptionBlock );

  // 4) the exception block's RVA, searched in .rdata: that hit is the C_SCOPE_TABLE entry
  ebAddr := DWORD( NativeUInt( exceptionBlock ) - NativeUInt( hNtdll ) );
  ebBytes[ 0 ] := Byte( ebAddr and $FF );
  ebBytes[ 1 ] := Byte( ( ebAddr shr 8 ) and $FF );
  ebBytes[ 2 ] := Byte( ( ebAddr shr 16 ) and $FF );
  ebBytes[ 3 ] := Byte( ( ebAddr shr 24 ) and $FF );
  scopeHit := MM_ScanSectionPattern( hNtdll, '.rdata', @ebBytes, 4, nil );
  if ( scopeHit = nil ) then
    Exit;

  // 5) C_SCOPE_TABLE$$Begin = *(DWORD*)(scopeHit-8) as RVA + image base, aligned down to 4
  block := PByte( NativeUInt( PDWORD( scopeHit - 8 )^ ) + NativeUInt( hNtdll ) );
  block := PByte( ( NativeUInt( block ) div 4 ) * 4 );
  blockBackup := block;

  // 6) walk back over 4 consecutive 0xCC (function padding), at most 0x400 DWORDs
  while ( PDWORD( block )^ <> $CCCCCCCC ) do
    begin
    if ( NativeUInt( blockBackup ) - NativeUInt( block ) > $1000 ) then // 0x400 DWORDs = 0x1000 bytes
      Exit;
    Dec( block, 4 );
    end;
  Inc( block, 4 );
  Result := block;
end;
{$ELSE}
// x86 (also covers WOW64 - the 32-bit ntdll a 32-bit process gets is the same binary either
// way): no string literal / C_SCOPE_TABLE trick like x64's (x86 doesn't have that unwind
// metadata), so this locates the function by its own machine code instead - an AOB/wildcard
// scan over its distinctive /GS+SEH prologue shape:
//   push <frame size>; push <ehdata>; call _SEH_prolog4_GS;   (standard MSVC /GS prologue)
//   mov eax,ecx                                                (FIXED - the sole parameter
//                                                                arrives in ECX, not on the
//                                                                stack - confirmed via live
//                                                                cdb disassembly; the PDB's
//                                                                "_LdrpHandleTlsData@4"
//                                                                decorated name is misleading
//                                                                here, it is NOT real stdcall)
//   mov [ebp-?],eax; mov [ebp-?],eax;                          (stash into two locals)
//   cmp dword ptr [LdrpActiveThreadCount],0; je ...             (opcodes fixed, operands vary)
// Measured unique (single hit, at the live, symbol-confirmed address) in .text on two
// Windows 11 24H2 builds (10.0.26100.7920 and 10.0.26100.8875); NOT yet confirmed against a
// genuine Windows 10 build (the actual field-reported target, see TODO.md's SignoTec note) -
// if the shape differs there this simply finds nothing and the feature self-disables, same
// best-effort contract as every other locator in this unit.
const
  Pat : array[ 0..32 ] of Byte = (
    $6A, $00, $68, $00, $00, $00, $00, $E8, $00, $00, $00, $00, $8B, $C1, $89, $45, $00,
    $89, $45, $00, $83, $3D, $00, $00, $00, $00, $00, $0F, $84, $00, $00, $00, $00 );
  Msk : array[ 0..32 ] of Byte = (
    $FF, $00, $FF, $00, $00, $00, $00, $FF, $00, $00, $00, $00, $FF, $FF, $FF, $FF, $00,
    $FF, $FF, $00, $FF, $FF, $00, $00, $00, $00, $FF, $FF, $FF, $00, $00, $00, $00 );
var
  hNtdll : Pointer;
begin
  Result := nil;
  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if ( hNtdll = nil ) then
    Exit;
  Result := MM_ScanSectionPatternMasked( hNtdll, '.text', @Pat, @Msk, SizeOf( Pat ), nil );
end;
{$ENDIF CPUX64}

// Locates ntdll!LdrpReleaseTlsEntry on Windows 10.0 x64 (port of
// MmpLdrpTls.cpp::RtlFindLdrpReleaseTlsEntry).
function MM_FindLdrpReleaseTlsEntry : Pointer;
{$IFDEF CPUX64}
const
  Feature : array[ 0..19 ] of Byte = (
    $48, $89, $5C, $24, $08, $57, $48, $83, $EC, $20,
    $48, $8B, $FA, $48, $8B, $D9, $48, $85, $D2, $75 );
var
  hNtdll : Pointer;
  vMajor, vMinor, vBuild : DWORD;
begin
  Result := nil;
  MM_RtlGetNtVersionNumbers( vMajor, vMinor, vBuild );
  if ( vMajor <> 10 ) OR ( vMinor <> 0 ) then
    Exit; // Win10.0 only (MmpLdrpTls.cpp gates on Major==10 && Minor==0)
  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if ( hNtdll = nil ) then
    Exit;
  Result := MM_ScanSectionPattern( hNtdll, '.text', @Feature, SizeOf( Feature ), nil );
end;
{$ELSE}
// x86/WOW64 counterpart of the locator above: LdrpReleaseTlsEntry(Entry, Opt) also takes BOTH
// its arguments in registers (ECX=Entry, EDX=Opt - confirmed live: "mov edi,edx; mov esi,ecx"
// is the very first thing the function does, before touching the stack at all), despite the
// PDB decorating it as "_LdrpReleaseTlsEntry@8". AOB/wildcard scan over its hot-patchable
// prologue (mov edi,edi; push ebx,esi,edi; the two register moves; mov ebx,<LdrpTlsLock>; ...).
// Same measured-unique-on-two-builds / not-yet-Win10-confirmed / self-disables-if-not-found
// caveats as MM_FindLdrpHandleTlsData10 above.
const
  Pat : array[ 0..32 ] of Byte = (
    $8B, $FF, $53, $56, $57, $8B, $FA, $8B, $F1, $BB, $00, $00, $00, $00, $85, $FF, $75,
    $00, $53, $E8, $00, $00, $00, $00, $8B, $CE, $E8, $00, $00, $00, $00, $8B, $F0 );
  Msk : array[ 0..32 ] of Byte = (
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $00, $00, $00, $00, $FF, $FF, $FF,
    $00, $FF, $FF, $00, $00, $00, $00, $FF, $FF, $FF, $00, $00, $00, $00, $FF, $FF );
var
  hNtdll : Pointer;
begin
  Result := nil;
  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if ( hNtdll = nil ) then
    Exit;
  Result := MM_ScanSectionPatternMasked( hNtdll, '.text', @Pat, @Msk, SizeOf( Pat ), nil );
end;
{$ENDIF CPUX64}

{$IFNDEF CPUX64}
// ntdll!LdrpHandleTlsData/LdrpReleaseTlsEntry on x86 take their arguments in ECX (/EDX) - see the
// locator comments above for the live-disassembly evidence. Delphi's own default ("register")
// calling convention instead puts the FIRST declared parameter in EAX, so a plain typed function
// pointer would pass Entry in the wrong register entirely. These thunks just move the already-
// loaded register-convention arguments into the registers the real ntdll routine expects, then
// CALL it (not a tail-jmp - that would skip whatever prologue/epilogue the compiler generates for
// this asm block, unbalancing the stack; a plain call/return is self-consistent regardless). The
// callee's return value ends up in EAX either way, which is also this thunk's own return register.
function MM_CallLdrpHandleTlsData_X86( Fn, Entry : Pointer ) : LongWord;
asm
  // register convention: EAX = Fn, EDX = Entry
  MOV ECX, EDX
  CALL EAX
end;

procedure MM_CallLdrpReleaseTlsEntry_X86( Fn, Entry, Opt : Pointer );
asm
  // register convention: EAX = Fn, EDX = Entry, ECX = Opt -> swap into ECX = Entry, EDX = Opt
  XCHG ECX, EDX
  CALL EAX
end;
{$ENDIF}

// One-time lazy setup: locate both ntdll routines; if either fails the feature stays disabled.
procedure MM_EnsureLdrpTls;
var
  hFn, rFn : Pointer;
begin
  if MM_LdrpTlsInitialized then
    Exit;
  MM_LdrpTlsInitialized := True;
  // Call the locators and use their RESULT (the located ntdll routine) as the function pointer.
  // (Using @locator here would install the locator itself, which returns the ntdll address as
  // its "status" - that was the bug that produced status 0x02714C00 == low32 of the address.)
  hFn := MM_FindLdrpHandleTlsData10;
  rFn := MM_FindLdrpReleaseTlsEntry;
  {$IFDEF CPUX64}
  MM_LdrpHandleTlsDataFn   := TMM_LdrpHandleTlsDataFn( hFn );
  MM_LdrpReleaseTlsEntryFn := TMM_LdrpReleaseTlsEntryFn( rFn );
  {$ELSE}
  MM_LdrpHandleTlsDataFn   := hFn; // plain Pointer on x86 - called only via the MM_CallLdrp*_X86
  MM_LdrpReleaseTlsEntryFn := rFn; // thunks, which know the real (register-based) convention
  {$ENDIF}
  if ( NOT Assigned( MM_LdrpHandleTlsDataFn ) ) OR ( NOT Assigned( MM_LdrpReleaseTlsEntryFn ) ) then
    begin
    MM_LdrpHandleTlsDataFn   := nil;
    MM_LdrpReleaseTlsEntryFn := nil;
    end;
end;

// Asks the loader to set up the module's dynamic TLS template. Must run after RegisterInPEB
// (the loader reads Entry->DllBase) and BEFORE any module code runs (threadvar in a TLS callback
// or in DllMain already needs the storage). Returns True on STATUS_SUCCESS.
function MM_HandleTlsData( module : PMemoryModule ) : Boolean;
var
  st : LongWord;
begin
  Result := False;
  MM_EnsureLdrpTls;
  if NOT Assigned( module ) then
    Exit;
  if NOT Assigned( module.ldrEntry ) then
    Exit;
  if NOT Assigned( MM_LdrpHandleTlsDataFn ) then
    Exit;
  {$IFDEF CPUX64}
  st := MM_LdrpHandleTlsDataFn( PMM_LDR_DATA_TABLE_ENTRY( module.ldrEntry ) );
  {$ELSE}
  st := MM_CallLdrpHandleTlsData_X86( MM_LdrpHandleTlsDataFn, module.ldrEntry );
  {$ENDIF}
  {$IFDEF DEBUG_TLS}
  WriteLn( 'DBG TLS: LdrpHandleTlsData -> status ', st );
  {$ENDIF}
  Result := ( st = MM_TLS_STATUS_SUCCESS );
end;

// Releases the TLS slots the loader gave the module. Must run before UnregisterFromPEB frees the
// fake LDR entry.
procedure MM_ReleaseTlsEntry( module : PMemoryModule );
begin
  MM_EnsureLdrpTls;
  if NOT Assigned( module ) then
    Exit;
  if NOT Assigned( module.ldrEntry ) then
    Exit;
  if NOT Assigned( MM_LdrpReleaseTlsEntryFn ) then
    Exit;
  {$IFDEF CPUX64}
  MM_LdrpReleaseTlsEntryFn( PMM_LDR_DATA_TABLE_ENTRY( module.ldrEntry ), nil );
  {$ELSE}
  MM_CallLdrpReleaseTlsEntry_X86( MM_LdrpReleaseTlsEntryFn, module.ldrEntry, nil );
  {$ENDIF}
end;
{$ENDIF MEMORY_HANDLE_TLS}

procedure MM_InsertTailList( ListHead, Entry : PMM_LIST_ENTRY );
var
  last : PMM_LIST_ENTRY;
begin
  last        := ListHead.Blink;
  Entry.Flink := ListHead;
  Entry.Blink := last;
  last.Flink  := Entry;
  ListHead.Blink := Entry;
end;

procedure MM_RemoveEntryList( Entry : PMM_LIST_ENTRY );
begin
  if ( Entry.Flink = nil ) OR ( Entry.Blink = nil ) then
    Exit; // never inserted
  Entry.Blink.Flink := Entry.Flink;
  Entry.Flink.Blink := Entry.Blink;
  Entry.Flink := nil;
  Entry.Blink := nil;
end;

// Allocates a UNICODE_STRING buffer on the process heap (must outlive the entry).
function MM_AllocUnicode( var U : MM_UNICODE_STRING; const S : string ) : Boolean;
var
  w    : WideString;
  cb   : Integer;
begin
  Result := False;
  w  := WideString( S );
  cb := ( Length( w ) + 1 ) * SizeOf( WideChar );
  U.Buffer := HeapAlloc( GetProcessHeap, HEAP_ZERO_MEMORY, cb );
  if ( U.Buffer = nil ) then
    Exit;
  if ( Length( w ) > 0 ) then
    Move( PWideChar( w )^, U.Buffer^, Length( w ) * SizeOf( WideChar ) );
  U.Length        := Length( w ) * SizeOf( WideChar );
  U.MaximumLength := cb;
  Result := True;
end;

procedure MM_FreeUnicode( var U : MM_UNICODE_STRING );
begin
  if Assigned( U.Buffer ) then
    HeapFree( GetProcessHeap, 0, U.Buffer );
  U.Buffer        := nil;
  U.Length        := 0;
  U.MaximumLength := 0;
end;

{$IFDEF MEMORY_LDR_HASH_TABLE}
// =================================================================================================
//  LdrpHashTable - name->module lookup
//  Faithful port of MemoryModulePP ( bb107 ): Initialize.cpp::FindLdrpHashTable /
//  IsValidLdrpHashTable + LdrEntry.cpp::LdrHashEntry / RtlInsertMemoryTableEntry. Since NT the
//  loader publishes every loaded module in ntdll's private LdrpHashTable (LDR_HASH_TABLE_ENTRIES =
//  32 buckets of LIST_ENTRY, the per-module head being the HashLinks field at offset 0x70/0x3C of
//  the LDR data table entry). LdrGetDllHandle (and therefore GetModuleHandle/GetModuleHandleEx by
//  name and GetModuleFileName) resolves names ONLY through that table, never through the three PEB
//  doubly-linked lists, so a memory module that is merely linked into the lists stays invisible to
//  name-based lookups. Inserting our fake entry's HashLinks into bucket LdrHashEntry(BaseDllName)
//  (RtlHashUnicodeString, Win8+ default case) makes the OS find it, mirroring ntdll's own
//  LdrpInsertDataTableEntry. Everything is best-effort and self-validating: the locator recomputes
//  the table start from a module that sits alone in its bucket and then verifies all 32 buckets,
//  so if the table or the hash function does not match this OS the feature silently disables
//  itself and load still succeeds. The load-time walk races with concurrent Load/FreeLibrary like
//  the original C++ does; the table is located once at first use.
// =================================================================================================
const
  MM_LDR_HASH_TABLE_ENTRIES = 32;
  // HashLinks field offset inside LDR_DATA_TABLE_ENTRY (stable prefix, matches the record above).
  MM_HASH_LINKS_OFFSET      = {$IFDEF CPUX64}$70{$ELSE}$3C{$ENDIF};
  // BaseNameHashValue (ULONG) field offset. ntdll's LdrpFindLoadedDllByName compares this hash
  // against the requested name BEFORE walking the strings, so an entry whose BaseNameHashValue is
  // stale (or zero from HEAP_ZERO_MEMORY) stays invisible even in the right bucket. x64 offset is
  // measured (see Test\Tls\TlsHashDiag [7]: zeroing $108-10B flips the lookup to "not found");
  // x86 offset derived from the phnt layout (BaseDllName $2C + 0x50).
  MM_BASE_NAME_HASH_VALUE_OFFSET = {$IFDEF CPUX64}$108{$ELSE}$8C{$ENDIF};

var
  MM_LdrpHashTable      : PMM_LIST_ENTRY = nil;   // located ntdll!LdrpHashTable[0]
  MM_LdrpHashTableTried : Boolean = False;

// ntdll export, available since Vista. BOOLEAN CaseInSensitive is a 1-byte 0/1 flag, so Byte.
function MM_RtlHashUnicodeString( Str : PMM_UNICODE_STRING; CaseInSensitive : Byte;
  HashAlgorithm : Cardinal; var HashValue : Cardinal ) : LongWord; stdcall;
  external 'ntdll.dll' name 'RtlHashUnicodeString';

// Port of LdrHashEntry (Win8+ default case): RtlHashUnicodeString(DllBaseName, TRUE,
// HASH_STRING_ALGORITHM_DEFAULT) masked to the bucket index. Older OS hashes differ, but the
// IsValidLdrpHashTable scan rejects them, so the feature degrades gracefully there.
function MM_LdrHashEntry( const DllBaseName : MM_UNICODE_STRING ) : Cardinal;
var
  h : Cardinal;
begin
  h := 0;
  if ( DllBaseName.Buffer <> nil ) then
    MM_RtlHashUnicodeString( @DllBaseName, 1, 0, h );
  Result := h AND ( MM_LDR_HASH_TABLE_ENTRIES - 1 );
end;

// Port of Initialize.cpp::IsValidLdrpHashTable: every module in bucket i must hash to i.
function MM_IsValidLdrpHashTable( Table : PMM_LIST_ENTRY ) : Boolean;
var
  i    : Cardinal;
  head : PMM_LIST_ENTRY;
  ent  : PMM_LIST_ENTRY;
  cur  : PMM_LDR_DATA_TABLE_ENTRY;
begin
  Result := False;
  if ( Table = nil ) then
    Exit;
  for i := 0 to MM_LDR_HASH_TABLE_ENTRIES - 1 do
    begin
    head := PMM_LIST_ENTRY( PByte( Table ) + i * SizeOf( MM_LIST_ENTRY ) );
    ent  := head.Flink;
    while ( ent <> head ) do
      begin
      cur := PMM_LDR_DATA_TABLE_ENTRY( PByte( ent ) - MM_HASH_LINKS_OFFSET );
      if ( MM_LdrHashEntry( cur.BaseDllName ) <> i ) then
        Exit;
      ent := ent.Flink;
      end;
    end;
  Result := True;
end;

// Port of Initialize.cpp::FindLdrpHashTable. Scans the initialization-order list; the first module
// whose HashLinks link points to a list head that points straight back (a singleton bucket) pins
// the table start: bucket head minus its hash index equals LdrpHashTable[0].
function MM_FindLdrpHashTable : PMM_LIST_ENTRY;
var
  ldr       : PMM_PEB_LDR_DATA;
  head      : PMM_LIST_ENTRY;
  ent       : PMM_LIST_ENTRY;
  cur       : PMM_LDR_DATA_TABLE_ENTRY;
  hashEntry : PMM_LIST_ENTRY;
  table     : PMM_LIST_ENTRY;
begin
  Result := nil;
  ldr := MM_GetLdr;
  if ( ldr = nil ) then
    Exit;
  head := @ldr.InInitializationOrderModuleList;
  ent  := head.Flink;
  while ( ent <> head ) do
    begin
    // InInitializationOrderLinks is the third LIST_ENTRY of the stable prefix.
    cur := PMM_LDR_DATA_TABLE_ENTRY( PByte( ent ) - 2 * SizeOf( MM_LIST_ENTRY ) );
    hashEntry := @cur.HashLinks;
    if ( hashEntry.Flink <> hashEntry ) AND ( hashEntry.Flink.Flink = hashEntry ) then
      begin
      table := PMM_LIST_ENTRY( PByte( hashEntry.Flink ) -
        MM_LdrHashEntry( cur.BaseDllName ) * SizeOf( MM_LIST_ENTRY ) );
      if MM_IsValidLdrpHashTable( table ) then
        begin
        Result := table;
        Exit;
        end;
      end;
    ent := ent.Flink;
    end;
end;

// One-time lazy setup. A benign race between threads re-running the locator is accepted (both
// write the same value).
procedure MM_EnsureLdrpHashTable;
begin
  if MM_LdrpHashTableTried then
    Exit;
  MM_LdrpHashTableTried := True;
  MM_LdrpHashTable := MM_FindLdrpHashTable;
end;

// Port of LdrEntry.cpp::RtlInsertMemoryTableEntry (hash-table part only): link HashLinks into
// bucket LdrHashEntry(BaseDllName). Also stores the full BaseNameHashValue like the real loader
// does - ntdll's LdrpFindLoadedDllByName compares that hash before the string, so without it the
// entry would stay invisible in the correct bucket.
procedure MM_InsertMemoryTableEntry( entry : PMM_LDR_DATA_TABLE_ENTRY );
var
  i : Cardinal;
  h : Cardinal;
begin
  if ( MM_LdrpHashTable = nil ) then
    Exit;
  h := 0;
  if ( entry.BaseDllName.Buffer <> nil ) then
    MM_RtlHashUnicodeString( @entry.BaseDllName, 1, 0, h );
  PDWORD( PByte( entry ) + MM_BASE_NAME_HASH_VALUE_OFFSET )^ := h;
  i := MM_LdrHashEntry( entry.BaseDllName );
  MM_InsertTailList( PMM_LIST_ENTRY( PByte( MM_LdrpHashTable ) + i * SizeOf( MM_LIST_ENTRY ) ),
                     @entry.HashLinks );
end;

// Counterpart: unlink HashLinks from its bucket. Safe when the entry was never inserted
// (MM_RemoveEntryList checks for nil links; HEAP_ZERO_MEMORY leaves them nil).
procedure MM_RemoveMemoryTableEntry( entry : PMM_LDR_DATA_TABLE_ENTRY );
begin
  MM_RemoveEntryList( @entry.HashLinks );
end;
{$ENDIF MEMORY_LDR_HASH_TABLE}

// Placeholder name used until the caller supplies the real one (the module must be registered
// before DllMain runs, and at that point only the base address is known).
function Format_MemModuleName( module : PMemoryModule ) : string;
const
  Hex : array[ 0..15 ] of Char = ( '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' );
var
  v : NativeUInt;
  s : string;
  i : Integer;
begin
  v := NativeUInt( module.codeBase );
  s := '';
  for i := 1 to SizeOf( Pointer ) * 2 do
    begin
    s := Hex[ v and $F ] + s;
    v := v shr 4;
    end;
  Result := 'MemModule_' + s + '.dll';
end;

// Links the module into the loader's module lists so the OS can attribute addresses inside the
// image to a module. Deliberately NOT linked into InInitializationOrderModuleList: that list is
// what LdrShutdownProcess walks to call DllMain(PROCESS_DETACH), and our module is detached and
// freed by MemoryFreeLibrary, so letting the loader call into freed memory must be avoided.
function RegisterInPEB( module : PMemoryModule; const AName : string ) : Boolean;
var
  ldr   : PMM_PEB_LDR_DATA;
  entry : PMM_LDR_DATA_TABLE_ENTRY;
  base  : string;
  i     : Integer;
begin
  Result := False;
  if NOT Assigned( module ) then
    Exit;
  if Assigned( module.ldrEntry ) then
    Exit; // already registered

  ldr := MM_GetLdr;
  if ( ldr = nil ) then
    Exit;

  entry := HeapAlloc( GetProcessHeap, HEAP_ZERO_MEMORY,
    {$IFDEF REGISTER_IN_BASE_ADDRESS_INDEX}
    MM_FAKE_ENTRY_SIZE // covers the RB node region and the loader-touched fields up to ReferenceCount
    {$ELSE}
    SizeOf( MM_LDR_DATA_TABLE_ENTRY )
    {$ENDIF}
  );
  if ( entry = nil ) then
    Exit;

  entry.DllBase := module.codeBase;
  if module.headers.X64 then
    begin
    entry.SizeOfImage := module.headers.headers64.OptionalHeader.SizeOfImage;
    if ( module.headers.headers64.OptionalHeader.AddressOfEntryPoint <> 0 ) then
      entry.EntryPoint := Pointer( NativeUInt( module.codeBase ) + module.headers.headers64.OptionalHeader.AddressOfEntryPoint );
    end
  else
    begin
    entry.SizeOfImage := module.headers.headers32.OptionalHeader.SizeOfImage;
    if ( module.headers.headers32.OptionalHeader.AddressOfEntryPoint <> 0 ) then
      entry.EntryPoint := Pointer( NativeUInt( module.codeBase ) + module.headers.headers32.OptionalHeader.AddressOfEntryPoint );
    end;

  // Pinned + "already processed", so the loader neither unloads nor re-initializes it.
  entry.Flags     := LDRP_IMAGE_DLL or LDRP_ENTRY_PROCESSED or LDRP_PROCESS_ATTACH_CALLED;
  entry.LoadCount := LDR_LOADCOUNT_PINNED;
  entry.TlsIndex  := 0;

  base := AName;
  for i := Length( base ) downTo 1 do
    if ( base[ i ] = '\' ) OR ( base[ i ] = '/' ) then
      begin
      base := Copy( base, i+1, Length( base )-i );
      Break;
      end;

  if ( NOT MM_AllocUnicode( entry.FullDllName, AName ) ) OR
     ( NOT MM_AllocUnicode( entry.BaseDllName, base ) ) then
    begin
    MM_FreeUnicode( entry.FullDllName );
    MM_FreeUnicode( entry.BaseDllName );
    HeapFree( GetProcessHeap, 0, entry );
    Exit;
    end;

  {$IFDEF REGISTER_IN_BASE_ADDRESS_INDEX}
  // Must precede the RB insert: ntdll's address->module lookup AddRefs the entry once it finds us.
  if NOT MM_InitFakeLdrDdagNode( entry ) then
    begin
    MM_FreeUnicode( entry.FullDllName );
    MM_FreeUnicode( entry.BaseDllName );
    HeapFree( GetProcessHeap, 0, entry );
    Exit;
    end;
  {$ENDIF REGISTER_IN_BASE_ADDRESS_INDEX}

  // The list heads live in the PEB; touching them races with the loader, so take the loader lock.
  MM_InsertTailList( @ldr.InLoadOrderModuleList,   @entry.InLoadOrderLinks );
  MM_InsertTailList( @ldr.InMemoryOrderModuleList, @entry.InMemoryOrderLinks );

  {$IFDEF REGISTER_IN_BASE_ADDRESS_INDEX}
  // Make the address->module lookup find us too. Must run before any module code (DllMain /
  // try-except) that RtlIsValidHandler might have to attribute to a module.
  MM_EnsureBaseAddressIndex;
  MM_InsertModuleBaseAddressIndexNode( entry, entry.DllBase );
  {$ENDIF REGISTER_IN_BASE_ADDRESS_INDEX}

  {$IFDEF MEMORY_LDR_HASH_TABLE}
  // Make GetModuleHandle(name) / GetModuleFileName find us by name. Uses the placeholder name set
  // above; UpdatePEBName re-links the entry once the real name is known.
  MM_EnsureLdrpHashTable;
  MM_InsertMemoryTableEntry( entry );
  {$ENDIF MEMORY_LDR_HASH_TABLE}

  module.ldrEntry := entry;
  Result := True;
end;

procedure UnregisterFromPEB( module : PMemoryModule );
var
  entry : PMM_LDR_DATA_TABLE_ENTRY;
begin
  if NOT Assigned( module ) then
    Exit;
  if NOT Assigned( module.ldrEntry ) then
    Exit;
  entry := PMM_LDR_DATA_TABLE_ENTRY( module.ldrEntry );

  {$IFDEF REGISTER_IN_BASE_ADDRESS_INDEX}
  MM_RemoveModuleBaseAddressIndexNode( entry ); // pull it out of the RB tree first
  MM_UnregisterFakeDdagNode( entry );
  {$ENDIF REGISTER_IN_BASE_ADDRESS_INDEX}

  {$IFDEF MEMORY_LDR_HASH_TABLE}
  MM_RemoveMemoryTableEntry( entry ); // unlink from the name hash table before freeing
  {$ENDIF MEMORY_LDR_HASH_TABLE}

  MM_RemoveEntryList( @entry.InLoadOrderLinks );
  MM_RemoveEntryList( @entry.InMemoryOrderLinks );

  MM_FreeUnicode( entry.FullDllName );
  MM_FreeUnicode( entry.BaseDllName );
  HeapFree( GetProcessHeap, 0, entry );
  module.ldrEntry := nil;
end;

// Updates the name shown to stack walkers once the caller knows it (the module is registered
// before DllMain runs, at which point only a placeholder name is available).
procedure UpdatePEBName( module : PMemoryModule; const AName : string );
var
  entry : PMM_LDR_DATA_TABLE_ENTRY;
  base  : string;
  i     : Integer;
begin
  if NOT Assigned( module ) then
    Exit;
  if NOT Assigned( module.ldrEntry ) then
    Exit;
  if ( AName = '' ) then
    Exit;
  entry := PMM_LDR_DATA_TABLE_ENTRY( module.ldrEntry );

  base := AName;
  for i := Length( base ) downTo 1 do
    if ( base[ i ] = '\' ) OR ( base[ i ] = '/' ) then
      begin
      base := Copy( base, i+1, Length( base )-i );
      Break;
      end;

  {$IFDEF MEMORY_LDR_HASH_TABLE}
  // The hash bucket is a function of BaseDllName: unlink the old name's bucket first, then re-link
  // under the new name after the strings are swapped.
  MM_RemoveMemoryTableEntry( entry );
  {$ENDIF MEMORY_LDR_HASH_TABLE}

  MM_FreeUnicode( entry.FullDllName );
  MM_FreeUnicode( entry.BaseDllName );
  MM_AllocUnicode( entry.FullDllName, AName );
  MM_AllocUnicode( entry.BaseDllName, base );

  {$IFDEF MEMORY_LDR_HASH_TABLE}
  MM_InsertMemoryTableEntry( entry );
  {$ENDIF MEMORY_LDR_HASH_TABLE}
end;
{$ENDIF REGISTER_IN_PEB}

// Registers the module's .pdata (exception/unwind) table with the OS so that exceptions thrown from
// inside a memory-loaded x64 image can be unwound and stack walkers can resolve its frames.
// Must run AFTER relocations (the table holds RVAs, but the OS needs the final image base) and
// BEFORE any code of the module executes (TLS callbacks / DllMain may already raise).
function RegisterExceptionTable( module : PMemoryModule ) : Boolean;
{$IFDEF CPUX64}
var
  directory : PIMAGE_DATA_DIRECTORY;
  count     : Cardinal;
begin
  Result := True; // "nothing to do" is not a failure
  if NOT Assigned( module ) then
    Exit;
  module.funcTable := nil;
  // 32-bit images use no .pdata unwind tables; they must not be registered.
  if NOT module.headers.X64 then
    Exit;

  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_EXCEPTION );
  if ( directory = nil ) OR ( directory.VirtualAddress = 0 ) OR ( directory.Size < SizeOf( TMM_RUNTIME_FUNCTION ) ) then
    Exit; // image without unwind data (rare, e.g. pure resource DLLs)

  count := directory.Size div SizeOf( TMM_RUNTIME_FUNCTION );
  if ( count = 0 ) then
    Exit;

  module.funcTable := Pointer( NativeUInt( module.codeBase ) + directory.VirtualAddress );
  Result := RtlAddFunctionTable( module.funcTable, count, UInt64( module.codeBase ) );
  if NOT Result then
    module.funcTable := nil; // nothing registered -> nothing to delete later
end;
{$ELSE}
begin
  Result := True; // no unwind tables on 32-bit
  if Assigned( module ) then
    module.funcTable := nil;
end;
{$ENDIF CPUX64}

// Counterpart of RegisterExceptionTable; safe to call when nothing was registered.
procedure UnregisterExceptionTable( module : PMemoryModule );
begin
  if NOT Assigned( module ) then
    Exit;
  {$IFDEF CPUX64}
  if Assigned( module.funcTable ) then
    begin
    RtlDeleteFunctionTable( module.funcTable );
    module.funcTable := nil;
    end;
  {$ELSE}
  module.funcTable := nil;
  {$ENDIF CPUX64}
end;

{$IF Defined( MEMORY_SEH_X86 ) AND NOT Defined( CPUX64 )}
// ===================================================================================================
//  x86 SEH support - ntdll!LdrpInvertedFunctionTable
//  Faithful port of MemoryModulePP ( bb107 ): InvertedFunctionTable.cpp + the x86 locator from
//  Initialize.cpp. All of this is undocumented and the memory layout differs between Windows 7 and
//  Windows 8+. Everything is best-effort: if the private table cannot be located the feature disables
//  itself and load still succeeds. The native imports below map 1:1 to JclNtApi / JwaNative / DDetours
//  declarations - swap them out if you prefer to reference those units.
// ===================================================================================================
const
  sd_LOAD_CONFIG_DIR = 10;    // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
  sd_COM_DIR         = 14;    // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
  sd_NO_SEH          = $0400; // IMAGE_DLLCHARACTERISTICS_NO_SEH
  sd_MEM_BASIC_INFO  = 0;     // MemoryBasicInformation

function sd_RtlGetNtVersionNumbers( var Major, Minor, Build : DWORD ) : DWORD; stdcall; external 'ntdll.dll' name 'RtlGetNtVersionNumbers';
function sd_RtlImageNtHeader( Base : Pointer ) : PIMAGE_NT_HEADERS32; stdcall; external 'ntdll.dll' name 'RtlImageNtHeader';
function sd_RtlImageDirectoryEntryToData( Base : Pointer; MappedAsImage : ByteBool; DirectoryEntry : Word; var Size : ULONG ) : Pointer; stdcall; external 'ntdll.dll' name 'RtlImageDirectoryEntryToData';
function sd_RtlEncodeSystemPointer( P : Pointer ) : Pointer; stdcall; external 'ntdll.dll' name 'RtlEncodeSystemPointer';
function sd_NtProtectVirtualMemory( Process : THandle; var BaseAddress : Pointer; var NumberOfBytes : NativeUInt; NewProtect : ULONG; var OldProtect : ULONG ) : LongInt; stdcall; external 'ntdll.dll' name 'NtProtectVirtualMemory';
function sd_NtQueryVirtualMemory( Process : THandle; BaseAddress : Pointer; MemoryInformationClass : LongInt; MemoryInformation : Pointer; MemoryInformationLength : NativeUInt; var ReturnLength : NativeUInt ) : LongInt; stdcall; external 'ntdll.dll' name 'NtQueryVirtualMemory';

type
  Psd_LoadConfig32 = ^Tsd_LoadConfig32;
  Tsd_LoadConfig32 = packed record
    Size           : DWORD;                 // +00
    Pad0           : array[ 0..$37 ] of Byte; // +04 .. +3B
    SecurityCookie : DWORD;                 // +3C
    SEHandlerTable : DWORD;                 // +40
    SEHandlerCount : DWORD;                 // +44
  end;

  Psd_Cor20 = ^Tsd_Cor20;
  Tsd_Cor20 = packed record
    cb                  : DWORD;               // +00
    MajorRuntimeVersion : Word;                // +04
    MinorRuntimeVersion : Word;                // +06
    MetaData            : TImageDataDirectory; // +08
    Flags               : DWORD;               // +10
  end;

  // WIN7_32 field meaning. The encoded SEH-table pointer of entry N lives in the NextEntry... slot of
  // the PREVIOUS entry (or in the table header for entry 0); this deliberate one-slot shift mirrors
  // the real in-memory layout and is what the byte pattern in the locator keys off.
  Psd_InvEntry = ^Tsd_InvEntry;
  Tsd_InvEntry = record
    ImageBase                      : Pointer;
    ImageSize                      : ULONG;
    SEHandlerCount                 : ULONG;
    NextEntrySEHandlerTableEncoded : Pointer;
  end;
  Psd_InvTable = ^Tsd_InvTable;
  Tsd_InvTable = record
    Count                          : ULONG;
    MaxCount                       : ULONG;
    Overflow                       : ULONG;  // Win8+: this slot is Epoch
    NextEntrySEHandlerTableEncoded : ULONG;  // Win8+: this slot is Overflow
    Entries                        : array[ 0..$1FF ] of Tsd_InvEntry;
  end;
  // Win8+ x86 reinterpretation of a 16-byte entry ( same size, x64 field order ).
  Psd_InvEntry8 = ^Tsd_InvEntry8;
  Tsd_InvEntry8 = record
    ExceptionDirectory     : Pointer; // holds the encoded SEH table pointer on x86
    ImageBase              : Pointer;
    ImageSize              : ULONG;
    ExceptionDirectorySize : ULONG;   // holds SEHandlerCount on x86
  end;

var
  sd_InvTable : Psd_InvTable = nil;
  sd_InvInit  : Boolean = False;
  sd_VerMajor : DWORD = 0;
  sd_VerMinor : DWORD = 0;
  sd_VerBuild : DWORD = 0;

function sd_IsWin8 : Boolean;
begin
  Result := ( sd_VerMajor > 6 ) OR ( ( sd_VerMajor = 6 ) AND ( sd_VerMinor >= 2 ) );
end;

function sd_IsWin81 : Boolean;
begin
  Result := ( sd_VerMajor > 6 ) OR ( ( sd_VerMajor = 6 ) AND ( sd_VerMinor >= 3 ) );
end;

function sd_GetPeb : Pointer;
asm
  MOV EAX, FS:[$30]
end;

function sd_Eq16( a, b : Pointer ) : Boolean;
begin
  Result := ( PDWORD( a )^ = PDWORD( b )^ ) AND
            ( PDWORD( PByte( a ) + 4 )^  = PDWORD( PByte( b ) + 4 )^ ) AND
            ( PDWORD( PByte( a ) + 8 )^  = PDWORD( PByte( b ) + 8 )^ ) AND
            ( PDWORD( PByte( a ) + 12 )^ = PDWORD( PByte( b ) + 12 )^ );
end;

function sd_SectionNameIs( sect : PImageSectionHeader; const Name : AnsiString ) : Boolean;
var
  i    : Integer;
  a, b : Byte;
begin
  Result := False;
  for i := 0 to 7 do
    begin
    a := sect.Name[ i ];
    if ( i < Length( Name ) ) then b := Byte( Name[ i+1 ] ) else b := 0;
    if ( a >= Ord( 'A' ) ) AND ( a <= Ord( 'Z' ) ) then Inc( a, 32 );
    if ( b >= Ord( 'A' ) ) AND ( b <= Ord( 'Z' ) ) then Inc( b, 32 );
    if ( a <> b ) then
      Exit;
    end;
  Result := True;
end;

// Reads the SafeSEH handler table / count from the image's load config ( -1/-1 means NO_SEH or .NET ).
function sd_CaptureImageExceptionValues( Base : Pointer; var SEHTable, SEHCount : DWORD ) : Boolean;
var
  nt  : PIMAGE_NT_HEADERS32;
  cfg : Psd_LoadConfig32;
  cor : Psd_Cor20;
  sz  : ULONG;
begin
  Result   := True;
  SEHTable := 0;
  SEHCount := 0;
  nt := sd_RtlImageNtHeader( Base );
  if ( nt <> nil ) AND ( ( nt.OptionalHeader.DllCharacteristics AND sd_NO_SEH ) <> 0 ) then
    begin
    SEHTable := $FFFFFFFF;
    SEHCount := $FFFFFFFF;
    Exit;
    end;
  sz  := 0;
  cfg := sd_RtlImageDirectoryEntryToData( Base, True, sd_LOAD_CONFIG_DIR, sz );
  if ( cfg <> nil ) AND ( sz = $40 ) AND ( cfg.Size >= $48 ) then
    if ( cfg.SEHandlerTable <> 0 ) AND ( cfg.SEHandlerCount <> 0 ) then
      begin
      SEHTable := cfg.SEHandlerTable;
      SEHCount := cfg.SEHandlerCount;
      Exit;
      end;
  sz  := 0;
  cor := sd_RtlImageDirectoryEntryToData( Base, True, sd_COM_DIR, sz );
  if ( cor <> nil ) AND ( ( cor.Flags AND 1 ) <> 0 ) then
    begin
    SEHTable := $FFFFFFFF;
    SEHCount := $FFFFFFFF;
    end;
end;

// Locate ntdll!LdrpInvertedFunctionTable by building the entry of the smallest-base module and
// pattern-scanning ntdll's .data ( Win7/8 ) or .mrdata ( Win8.1+ ) section for it.
function sd_FindInvertedTable : Psd_InvTable;
var
  hNtdll, smallest, hMod : Pointer;
  peb, ldr, head, cur    : PByte;
  ntMod, ntNtdll         : PIMAGE_NT_HEADERS32;
  sect                   : PImageSectionHeader;
  refEntry               : Tsd_InvEntry;
  sehTab, sehCnt         : DWORD;
  secName                : AnsiString;
  offset                 : Cardinal;
  base, scanEnd, p       : PByte;
  vsize                  : Cardinal;
  i                      : Integer;
  tab                    : Psd_InvTable;
begin
  Result := nil;
  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if hNtdll = nil then
    Exit;

  offset := $20; // 2 * SizeOf( entry )
  if sd_IsWin81 then
    secName := '.mrdata'
  else if NOT sd_IsWin8 then
    begin
    secName := '.data';
    offset  := $0C;
    end
  else
    secName := '.data';

  // smallest-base loaded module ( skip ntdll on Win8+ where it may be the first entry )
  peb  := sd_GetPeb;
  ldr  := PPointer( peb + $0C )^;
  head := PByte( ldr + $14 );
  cur  := PPointer( head )^;
  smallest := nil;
  while cur <> head do
    begin
    hMod := PPointer( cur + $10 )^; // DllBase ( InMemoryOrderLinks @+8 -> DllBase @+0x18 )
    if ( hMod <> nil ) AND NOT ( ( hMod = hNtdll ) AND ( offset = $20 ) ) then
      if ( smallest = nil ) OR ( NativeUInt( hMod ) < NativeUInt( smallest ) ) then
        smallest := hMod;
    cur := PPointer( cur )^; // Flink
    end;
  if smallest = nil then
    Exit;

  ntMod := sd_RtlImageNtHeader( smallest );
  if ntMod = nil then
    Exit;

  sd_CaptureImageExceptionValues( smallest, sehTab, sehCnt );
  // reference bytes: [ encoded(SEHTable) ][ ImageBase ][ SizeOfImage ][ SEHandlerCount ]
  refEntry.ImageBase                      := sd_RtlEncodeSystemPointer( Pointer( sehTab ) );
  refEntry.ImageSize                      := ULONG( smallest );
  refEntry.SEHandlerCount                 := ntMod.OptionalHeader.SizeOfImage;
  refEntry.NextEntrySEHandlerTableEncoded := Pointer( sehCnt );

  ntNtdll := sd_RtlImageNtHeader( hNtdll );
  if ntNtdll = nil then
    Exit;
  sect  := IMAGE_FIRST_SECTION( PIMAGE_NT_HEADERS32( ntNtdll ) );
  base  := nil;
  vsize := 0;
  for i := 0 to ntNtdll.FileHeader.NumberOfSections - 1 do
    begin
    if sd_SectionNameIs( sect, secName ) then
      begin
      base  := PByte( NativeUInt( hNtdll ) + sect.VirtualAddress );
      vsize := sect.Misc.VirtualSize;
      Break;
      end;
    Inc( sect );
    end;
  if ( base = nil ) OR ( vsize < SizeOf( refEntry ) ) then
    Exit;

  scanEnd := PByte( NativeUInt( base ) + vsize - SizeOf( refEntry ) );
  p := base;
  while NativeUInt( p ) <= NativeUInt( scanEnd ) do
    begin
    if sd_Eq16( p, @refEntry ) then
      begin
      tab := Psd_InvTable( PByte( NativeUInt( p ) - offset ) );
      if sd_IsWin8 then
        begin
        if ( tab.MaxCount = $200 ) AND ( tab.NextEntrySEHandlerTableEncoded = 0 ) then
          begin Result := tab; Exit; end;
        end
      else
        begin
        if ( tab.MaxCount = $200 ) AND ( tab.Overflow = 0 ) then
          begin Result := tab; Exit; end;
        end;
      end;
    Inc( p );
    end;
end;

// Lazily locates the table on first use and caches it ( nil = unavailable on this OS ).
function sd_InvertedTable : Psd_InvTable;
begin
  if NOT sd_InvInit then
    begin
    sd_RtlGetNtVersionNumbers( sd_VerMajor, sd_VerMinor, sd_VerBuild );
    sd_VerBuild := sd_VerBuild AND $FFFF;
    {$IFNDEF MEMORY_SEH_X86_ALLOW_UNTESTED}
    // NOTE (2026-08-07): this gate's original reasoning ("Win11 24H2+ table layout drifted") was
    // wrong and has been superseded - see TODO.md item 2. The table locator/insertion below is
    // confirmed correct on BOTH Windows 10.0.19045 and Windows 11 26200 (MemorySehX86Available
    // reports TRUE, FROM_ADDRESS resolves correctly on both). The real, still-unresolved problem is
    // that RtlIsValidHandler rejects a /SAFESEH-less module's own handler (which is what every
    // Delphi-built DLL is) unless it's backed by genuine MEM_IMAGE memory or the process has
    // ProcessExecuteFlags.IMAGE_DISPATCH_ENABLE set (typically unavailable, DEP Permanent) - and
    // this reproduces identically on Windows 10 and 11, so it is NOT a Windows-11-only issue. This
    // Win11-only gate is being left in place as-is (removing it wouldn't make exceptions survive
    // there either, per TODO.md item 2, and it's a harmless no-op difference at this point) but its
    // premise should not be trusted; do not extend or copy this "OS version gate" pattern elsewhere
    // without re-deriving the actual condition first.
    if ( sd_VerMajor > 10 ) OR ( ( sd_VerMajor = 10 ) AND ( sd_VerBuild >= 22000 ) ) then
      sd_InvTable := nil
    else
    {$ENDIF}
      sd_InvTable := sd_FindInvertedTable;
    sd_InvInit  := True;
    end;
  Result := sd_InvTable;
end;

// Win8.1+ keeps the table in read-only .mrdata; flip protection around every modification.
function sd_ProtectMrdata( tab : Psd_InvTable; NewProtect : ULONG ) : Boolean;
var
  mbi  : TMemoryBasicInformation;
  rl   : NativeUInt;
  base : Pointer;
  size : NativeUInt;
  old  : ULONG;
begin
  Result := False;
  rl := 0;
  if sd_NtQueryVirtualMemory( GetCurrentProcess, tab, sd_MEM_BASIC_INFO, @mbi, SizeOf( mbi ), rl ) < 0 then
    Exit;
  base := mbi.BaseAddress;
  size := mbi.RegionSize;
  old  := 0;
  Result := sd_NtProtectVirtualMemory( GetCurrentProcess, base, size, NewProtect, old ) >= 0;
end;

procedure sd_InsertEntry( tab : Psd_InvTable; ImageBase : Pointer; SizeOfImage : ULONG );
var
  idx, cnt   : ULONG;
  ptr, count : DWORD;
  isWin8     : Boolean;
  e8         : Psd_InvEntry8;
begin
  isWin8 := sd_IsWin8;
  idx    := Ord( isWin8 ); // Win8+ keeps entry 0 fixed ( ntdll )
  cnt    := tab.Count;
  if cnt = tab.MaxCount then
    begin
    if isWin8 then tab.NextEntrySEHandlerTableEncoded := 1 // Overflow
    else tab.Overflow := 1;
    Exit;
    end;

  while idx < cnt do
    begin
    if isWin8 then
      begin
      if NativeUInt( ImageBase ) < NativeUInt( Psd_InvEntry8( @tab.Entries[ idx ] ).ImageBase ) then Break;
      end
    else
      begin
      if NativeUInt( ImageBase ) < NativeUInt( tab.Entries[ idx ].ImageBase ) then Break;
      end;
    Inc( idx );
    end;

  if idx <> cnt then
    begin
    if isWin8 then
      Move( tab.Entries[ idx ], tab.Entries[ idx + 1 ], ( cnt - idx ) * SizeOf( Tsd_InvEntry ) )
    else if idx <> 0 then
      Move( tab.Entries[ idx - 1 ].NextEntrySEHandlerTableEncoded, tab.Entries[ idx ].NextEntrySEHandlerTableEncoded, ( cnt - idx ) * SizeOf( Tsd_InvEntry ) )
    else
      Move( tab.NextEntrySEHandlerTableEncoded, tab.Entries[ 0 ].NextEntrySEHandlerTableEncoded, ( cnt - idx ) * SizeOf( Tsd_InvEntry ) );
    end;

  sd_CaptureImageExceptionValues( ImageBase, ptr, count );
  if isWin8 then
    begin
    e8 := Psd_InvEntry8( @tab.Entries[ idx ] );
    e8.ExceptionDirectory     := sd_RtlEncodeSystemPointer( Pointer( ptr ) );
    e8.ExceptionDirectorySize := count;
    e8.ImageBase              := ImageBase;
    e8.ImageSize              := SizeOfImage;
    end
  else
    begin
    if idx <> 0 then tab.Entries[ idx - 1 ].NextEntrySEHandlerTableEncoded := sd_RtlEncodeSystemPointer( Pointer( ptr ) )
    else tab.NextEntrySEHandlerTableEncoded := DWORD( sd_RtlEncodeSystemPointer( Pointer( ptr ) ) );
    tab.Entries[ idx ].ImageBase      := ImageBase;
    tab.Entries[ idx ].ImageSize      := SizeOfImage;
    tab.Entries[ idx ].SEHandlerCount := count;
    end;

  Inc( tab.Count );
end;

procedure sd_RemoveEntry( tab : Psd_InvTable; ImageBase : Pointer );
var
  idx, cnt : ULONG;
  isWin8   : Boolean;
begin
  isWin8 := sd_IsWin8;
  cnt    := tab.Count;
  idx    := 0;
  while idx < cnt do
    begin
    if isWin8 then
      begin if Psd_InvEntry8( @tab.Entries[ idx ] ).ImageBase = ImageBase then Break; end
    else
      begin if tab.Entries[ idx ].ImageBase = ImageBase then Break; end;
    Inc( idx );
    end;

  if idx <> cnt then
    begin
    if cnt <> 1 then
      begin
      if isWin8 then
        Move( tab.Entries[ idx + 1 ], tab.Entries[ idx ], ( cnt - idx ) * SizeOf( Tsd_InvEntry ) )
      else if idx <> 0 then
        Move( tab.Entries[ idx ].NextEntrySEHandlerTableEncoded, tab.Entries[ idx - 1 ].NextEntrySEHandlerTableEncoded, ( cnt - idx ) * SizeOf( Tsd_InvEntry ) )
      else
        Move( tab.Entries[ idx ].NextEntrySEHandlerTableEncoded, tab.NextEntrySEHandlerTableEncoded, ( cnt - idx ) * SizeOf( Tsd_InvEntry ) );
      end;
    Dec( tab.Count );
    end;

  if tab.Count <> tab.MaxCount then
    begin
    if isWin8 then tab.NextEntrySEHandlerTableEncoded := 0
    else tab.Overflow := 0;
    end;
end;

function RegisterInvertedFunctionTableEntry( module : PMemoryModule ) : Boolean;
var
  tab      : Psd_InvTable;
  needProt : Boolean;
begin
  Result := False;
  if NOT Assigned( module ) then
    Exit;
  if module.headers.X64 then // x86 images only
    Exit;
  tab := sd_InvertedTable;
  if tab = nil then // could not locate the table -> silently unsupported on this OS
    Exit;
  needProt := sd_IsWin81;
  if needProt AND NOT sd_ProtectMrdata( tab, PAGE_READWRITE ) then
    Exit;
  sd_InsertEntry( tab, module.codeBase, module.headers.headers32.OptionalHeader.SizeOfImage );
  if needProt then
    sd_ProtectMrdata( tab, PAGE_READONLY );
  module.sehX86Registered := True;
  Result := True;
end;

function MemorySehX86Available : Boolean;
begin
  Result := sd_InvertedTable <> nil;
end;

function MemorySehX86TableInfo( var Table : Pointer; var Count, MaxCount : DWORD ) : Boolean;
var
  t : Psd_InvTable;
begin
  Table    := nil;
  Count    := 0;
  MaxCount := 0;
  t := sd_InvertedTable;
  Result := ( t <> nil );
  if Result then
    begin
    Table    := t;
    Count    := t.Count;
    MaxCount := t.MaxCount;
    end;
end;

function MemorySehX86IndexOf( ImageBase : Pointer ) : Integer;
var
  t : Psd_InvTable;
  i : Integer;
  b : Pointer;
begin
  Result := -1;
  t := sd_InvertedTable;
  if ( t = nil ) then
    Exit;
  for i := 0 to Integer( t.Count ) - 1 do
    begin
    if sd_IsWin8 then
      b := Psd_InvEntry8( @t.Entries[ i ] ).ImageBase
    else
      b := t.Entries[ i ].ImageBase;
    if ( b = ImageBase ) then
      begin
      Result := i;
      Exit;
      end;
    end;
end;

function MemorySehX86EntryOf( ImageBase : Pointer; var RawExcDir : Pointer; var Count : DWORD ) : Integer;
var
  t : Psd_InvTable;
  i : Integer;
  e8 : Psd_InvEntry8;
begin
  Result    := -1;
  RawExcDir := nil;
  Count     := 0;
  t := sd_InvertedTable;
  if ( t = nil ) then
    Exit;
  for i := 0 to Integer( t.Count ) - 1 do
    if sd_IsWin8 then
      begin
      e8 := Psd_InvEntry8( @t.Entries[ i ] );
      if ( e8.ImageBase = ImageBase ) then
        begin
        RawExcDir := e8.ExceptionDirectory;      // encoded SEH table pointer
        Count     := e8.ExceptionDirectorySize;  // = SEHandlerCount on x86
        Result    := i;
        Exit;
        end;
      end
    else
      begin
      if ( t.Entries[ i ].ImageBase = ImageBase ) then
        begin
        Count  := t.Entries[ i ].SEHandlerCount;
        Result := i;
        Exit;
        end;
      end;
end;

procedure UnregisterInvertedFunctionTableEntry( module : PMemoryModule );
var
  tab      : Psd_InvTable;
  needProt : Boolean;
begin
  if NOT Assigned( module ) then
    Exit;
  if NOT module.sehX86Registered then
    Exit;
  tab := sd_InvTable;
  if tab = nil then
    Exit;
  needProt := sd_IsWin81;
  if needProt AND NOT sd_ProtectMrdata( tab, PAGE_READWRITE ) then
    Exit;
  sd_RemoveEntry( tab, module.codeBase );
  if needProt then
    sd_ProtectMrdata( tab, PAGE_READONLY );
  module.sehX86Registered := False;
end;
{$IFEND MEMORY_SEH_X86}

{$IF Defined( MEMORY_FROM_ADDRESS_X64 ) AND Defined( CPUX64 )}
// ===================================================================================================
//  x64 FROM_ADDRESS support - ntdll!LdrpInvertedFunctionTable
//  GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) and RtlPcToFileHeader do not consult the
//  loader's module lists or LdrpModuleBaseAddressIndex at all - found by decompiling ntdll.dll with
//  IDA (no debugger was available in that session; see TODO.md item 1 for the full investigation,
//  including the experiments that ruled out the RB-tree/PEB-list approach first). Both APIs resolve
//  address->module through RtlpxLookupFunctionTable, the x64 SEH *unwind* function-table lookup:
//    - Fast path: binary-search a private, FIXED 512-entry ntdll array (LdrpInvertedFunctionTable),
//      populated only by the loader itself when it loads a real module. This is a DIFFERENT table
//      from the one the public RtlAddFunctionTable API writes to (already called unconditionally on
//      x64 by RegisterExceptionTable, for exception unwinding) - confirmed empirically that a
//      successful RtlAddFunctionTable call does not make RtlPcToFileHeader find the module.
//    - Slow/universal fallback: NtQueryVirtualMemory(MemoryImageInformation), which would accept any
//      genuine image mapping - but it only activates once the fixed 512-entry array has overflowed at
//      least once in this process, which essentially never happens, so it cannot be relied on.
//  This block inserts a real entry into that fixed array the same way the loader does, mirroring
//  ntdll's own (unexported) RtlpInsertInvertedFunctionTableEntry. Layout (header: Count, MaxCount,
//  Epoch, Overflow, each a DWORD, followed by 24-byte entries: FunctionTable ptr, ImageBase ptr,
//  SizeOfImage, ExceptionDirectorySize) was reverse-engineered via Hex-Rays decompilation and then
//  cross-checked field-by-field against a live process (the on-disk ntdll.dll has the table
//  zero-filled - it's populated by the loader at process init, so static analysis alone cannot
//  confirm field values, only offsets and control flow). Entry index 0 is permanently reserved for
//  ntdll itself and is also how the table is located here: pattern-scan ntdll's own .mrdata section
//  for ntdll's own entry bytes. Same caveats as MEMORY_SEH_X86 / REGISTER_IN_BASE_ADDRESS_INDEX:
//  undocumented, best-effort (silently disables if the table or its expected shape - MaxCount=512 -
//  cannot be confirmed), and races with the loader if another thread loads/unloads a module
//  concurrently while we're inserting/removing (the existing MEMORY_SEH_X86 code accepts the same
//  trade-off rather than trying to reimplement ntdll's own lock acquisition here).
// ===================================================================================================
const
  fa_MAX_ENTRIES = $200; // measured capacity on Windows 10.0.26100 (24H2/25H2); also re-checked at runtime

type
  Pfa_Entry = ^Tfa_Entry;
  Tfa_Entry = record
    FunctionTable          : Pointer; // raw VA of the module's .pdata ( IMAGE_DIRECTORY_ENTRY_EXCEPTION )
    ImageBase               : Pointer;
    SizeOfImage              : Cardinal;
    ExceptionDirectorySize   : Cardinal; // byte size of the .pdata directory - verified against a live
                                          // process, this is a real field, not padding
  end;

  Pfa_Table = ^Tfa_Table;
  Tfa_Table = record
    Count    : Cardinal;
    MaxCount : Cardinal;
    Epoch    : Cardinal; // bumped on every insert/remove by the real loader; kept in sync, not relied upon
    Overflow : Cardinal; // low byte latches permanently once an insert is attempted at MaxCount
    Entries  : array[ 0..fa_MAX_ENTRIES - 1 ] of Tfa_Entry;
  end;

function fa_RtlImageNtHeader( Base : Pointer ) : PIMAGE_NT_HEADERS64; stdcall; external 'ntdll.dll' name 'RtlImageNtHeader';

var
  fa_Table      : Pfa_Table = nil;
  fa_TableTried : Boolean = False;

function fa_SectionNameIs( sect : PImageSectionHeader; const Name : AnsiString ) : Boolean;
var
  i    : Integer;
  a, b : Byte;
begin
  Result := False;
  for i := 0 to 7 do
    begin
    a := sect.Name[ i ];
    if ( i < Length( Name ) ) then b := Byte( Name[ i+1 ] ) else b := 0;
    if ( a <> b ) then
      Exit;
    end;
  Result := True;
end;

function fa_MemCompare( P1, P2 : Pointer; Len : NativeUInt ) : Boolean;
var
  a, b : PByte;
begin
  a := P1;
  b := P2;
  Result := False;
  while ( Len > 0 ) do
    begin
    if ( a^ <> b^ ) then
      Exit;
    Inc( a );
    Inc( b );
    Dec( Len );
    end;
  Result := True;
end;

// Locates ntdll!LdrpInvertedFunctionTable by pattern-scanning ntdll's own .mrdata section for
// ntdll's own entry. Index 0 is always ntdll - populated at process init before any other module,
// and RtlPcToFileHeader's own outer wrapper special-cases index 0 directly - so this is a stable,
// version-independent anchor, the same style of locator REGISTER_IN_BASE_ADDRESS_INDEX and
// MEMORY_SEH_X86 already use (pattern-scan a KNOWN entry's bytes rather than hardcode an RVA).
function fa_FindTable : Pfa_Table;
var
  hNtdll     : Pointer;
  nt         : PIMAGE_NT_HEADERS64;
  excDir     : TImageDataDirectory;
  refBytes   : array[ 0..19 ] of Byte; // FunctionTable(8) + ImageBase(8) + SizeOfImage(4)
  sect       : PImageSectionHeader;
  base, e, p : PByte;
  vsize      : NativeUInt;
  i          : Integer;
begin
  Result := nil;
  hNtdll := Pointer( GetModuleHandleA( 'ntdll.dll' ) );
  if ( hNtdll = nil ) then
    Exit;
  nt := fa_RtlImageNtHeader( hNtdll );
  if ( nt = nil ) then
    Exit;
  excDir := nt.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];
  if ( excDir.Size = 0 ) then
    Exit;

  PPointer( @refBytes[ 0 ] )^   := Pointer( NativeUInt( hNtdll ) + excDir.VirtualAddress );
  PPointer( @refBytes[ 8 ] )^   := hNtdll;
  PCardinal( @refBytes[ 16 ] )^ := nt.OptionalHeader.SizeOfImage;

  sect  := PImageSectionHeader( PByte( @nt.OptionalHeader ) + nt.FileHeader.SizeOfOptionalHeader );
  base  := nil;
  vsize := 0;
  for i := 0 to nt.FileHeader.NumberOfSections - 1 do
    begin
    if fa_SectionNameIs( sect, '.mrdata' ) then
      begin
      base  := PByte( NativeUInt( hNtdll ) + sect.VirtualAddress );
      vsize := sect.Misc.VirtualSize;
      Break;
      end;
    Inc( sect );
    end;
  if ( base = nil ) OR ( vsize < SizeOf( refBytes ) ) then
    Exit; // no .mrdata section on this OS -> feature unavailable

  e := base + vsize - SizeOf( refBytes );
  p := base;
  while ( NativeUInt( p ) <= NativeUInt( e ) ) do
    begin
    if fa_MemCompare( p, @refBytes[ 0 ], SizeOf( refBytes ) ) then
      begin
      // header ( Count, MaxCount, Epoch, Overflow - 16 bytes ) precedes Entries[0]
      Result := Pfa_Table( p - 16 );
      if ( Result.MaxCount <> fa_MAX_ENTRIES ) then
        Result := nil; // unexpected layout on this OS -> refuse rather than risk corrupting .mrdata
      Exit;
      end;
    Inc( p );
    end;
end;

// Lazily locates the table on first use and caches it ( nil = unavailable on this OS ).
function fa_InvertedTable : Pfa_Table;
begin
  if NOT fa_TableTried then
    begin
    fa_Table      := fa_FindTable;
    fa_TableTried := True;
    end;
  Result := fa_Table;
end;

// The table lives in .mrdata, read-only after process init; flip protection around every write,
// the same VirtualProtect dance MEMORY_SEH_X86 already does for its own Win8.1+ .mrdata table.
function fa_ProtectMrdata( tab : Pfa_Table; NewProtect : DWORD ) : Boolean;
var
  old : DWORD;
begin
  Result := VirtualProtect( tab, SizeOf( Tfa_Table ), NewProtect, old );
end;

// Sorted insert, mirroring ntdll's own ( unexported ) RtlpInsertInvertedFunctionTableEntry as
// recovered from its decompilation. Index 0 is reserved for ntdll and never touched; entries
// [1..Count-1] are kept sorted ascending by ImageBase, matching the binary search
// RtlpxLookupFunctionTable performs over this same range.
function fa_InsertEntry( tab : Pfa_Table; FunctionTable, ImageBase : Pointer;
  SizeOfImage, ExceptionDirectorySize : Cardinal ) : Boolean;
var
  idx : Cardinal;
begin
  Result := False;
  if ( tab.Count = tab.MaxCount ) then
    begin
    tab.Overflow := 1; // matches the real loader: latch the "array exhausted" fallback flag
    Exit;
    end;

  idx := 1; // skip index 0 ( ntdll )
  while ( idx < tab.Count ) AND ( NativeUInt( ImageBase ) >= NativeUInt( tab.Entries[ idx ].ImageBase ) ) do
    Inc( idx );

  if ( idx <> tab.Count ) then
    Move( tab.Entries[ idx ], tab.Entries[ idx + 1 ], ( tab.Count - idx ) * SizeOf( Tfa_Entry ) );

  tab.Entries[ idx ].FunctionTable         := FunctionTable;
  tab.Entries[ idx ].ImageBase             := ImageBase;
  tab.Entries[ idx ].SizeOfImage           := SizeOfImage;
  tab.Entries[ idx ].ExceptionDirectorySize := ExceptionDirectorySize;

  Inc( tab.Count );
  Inc( tab.Epoch );
  Result := True;
end;

procedure fa_RemoveEntry( tab : Pfa_Table; ImageBase : Pointer );
var
  idx : Cardinal;
begin
  idx := 1; // skip index 0 ( ntdll )
  while ( idx < tab.Count ) AND ( tab.Entries[ idx ].ImageBase <> ImageBase ) do
    Inc( idx );
  if ( idx = tab.Count ) then
    Exit; // not found -> nothing to do

  if ( idx < tab.Count - 1 ) then
    Move( tab.Entries[ idx + 1 ], tab.Entries[ idx ], ( tab.Count - idx - 1 ) * SizeOf( Tfa_Entry ) );
  Dec( tab.Count );
  Inc( tab.Epoch );
  if ( tab.Count <> tab.MaxCount ) then
    tab.Overflow := 0;
end;

// Must run AFTER RegisterExceptionTable ( needs module.funcTable, the already-computed raw VA of
// the module's .pdata ) and, like it, before any module code executes.
function RegisterInvertedFunctionTableEntryX64( module : PMemoryModule ) : Boolean;
var
  tab       : Pfa_Table;
  directory : PIMAGE_DATA_DIRECTORY;
begin
  Result := False;
  if NOT Assigned( module ) then
    Exit;
  if NOT module.headers.X64 then
    Exit;
  if NOT Assigned( module.funcTable ) then
    Exit; // RegisterExceptionTable found no .pdata -> nothing to register here either

  tab := fa_InvertedTable;
  if ( tab = nil ) then
    Exit; // could not locate the table -> silently unsupported on this OS

  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_EXCEPTION );
  if NOT fa_ProtectMrdata( tab, PAGE_READWRITE ) then
    Exit;
  try
    Result := fa_InsertEntry( tab, module.funcTable, module.codeBase,
      module.headers.headers64.OptionalHeader.SizeOfImage, directory.Size );
  finally
    fa_ProtectMrdata( tab, PAGE_READONLY );
  end;
  module.faX64Registered := Result;
end;

procedure UnregisterInvertedFunctionTableEntryX64( module : PMemoryModule );
var
  tab : Pfa_Table;
begin
  if NOT Assigned( module ) then
    Exit;
  if NOT module.faX64Registered then
    Exit;
  tab := fa_Table; // already located earlier ( for this table to be registered at all ), don't re-search
  if ( tab = nil ) then
    Exit;
  if fa_ProtectMrdata( tab, PAGE_READWRITE ) then
    begin
    fa_RemoveEntry( tab, module.codeBase );
    fa_ProtectMrdata( tab, PAGE_READONLY );
    end;
  module.faX64Registered := False;
end;

function MemoryFromAddressX64Available : Boolean;
begin
  Result := fa_InvertedTable <> nil;
end;
{$IFEND MEMORY_FROM_ADDRESS_X64}

function ExecuteTLS( module: PMemoryModule ): Boolean;
var
  codeBase: Pointer;
  // TLS callback pointers are VA's ( ImageBase included ) so if the module resides at
  // the other ImageBage they become invalid. This routine relocates them to the
  // actual ImageBase.
  // The case seem to happen with DLLs only and they rarely use TLS callbacks.
  // Moreover, they probably don't work at all when using DLL dynamically which is
  // the case in our code.
  function FixPtr( OldPtr: Pointer ): Pointer;
  begin
    if module.headers.X64 then
      Result := Pointer( NativeInt( OldPtr ) - Int64( module.headers.headers64.OptionalHeader.ImageBase + NativeUInt( codeBase ) ) )
    else
      Result := Pointer( NativeInt( OldPtr ) - Integer( module.headers.headers32.OptionalHeader.ImageBase + NativeUInt( codeBase ) ) );
  end;
var
  directory: PIMAGE_DATA_DIRECTORY;
  tls: PIMAGE_TLS_DIRECTORY32;
  callback: PPointer; // =^PIMAGE_TLS_CALLBACK;
begin
  Result := False;
  codeBase := module.codeBase;

  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_TLS );
  if directory.VirtualAddress = 0 then
    Exit;
  tls := PIMAGE_TLS_DIRECTORY32( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codeBase ) + directory.VirtualAddress );

  // Delphi syntax is quite awkward when dealing with proc pointers so we have to
  // use casts to untyped pointers
  if module.headers.X64 then
    callback := Pointer( PIMAGE_TLS_DIRECTORY64( tls ).AddressOfCallBacks )
  else
    callback := Pointer( tls.AddressOfCallBacks );
  if callback <> nil then
    begin
    callback := FixPtr( callback );
    if module.headers.X64 then
      begin
      if ( NativeUInt( callback ) < NativeUInt( module^.codeBase ) ) or
         ( NativeUInt( callback ) >= NativeUInt( module^.codeBase ) + Module^.headers.headers64.OptionalHeader.SizeOfCode ) then
        Exit;
      end
    else
      begin
      if ( NativeUInt( callback ) < NativeUInt( module^.codeBase ) ) or
         ( NativeUInt( callback ) >= NativeUInt( module^.codeBase ) + Module^.headers.headers32.OptionalHeader.SizeOfCode ) then
        Exit;
      end;

    try
      while callback^ <> nil do
        begin
        PIMAGE_TLS_CALLBACK( FixPtr( callback^ ) )( codeBase, DLL_PROCESS_ATTACH, nil );
        Inc( callback );
        end;
    except
      Exit;
    end;
    end
  else
    Exit;
  Result := True;
end;

function PerformBaseRelocation( module: PMemoryModule; delta: Int64 ): Boolean;
var
  i: Cardinal;
  codebase: Pointer;
  directory: PIMAGE_DATA_DIRECTORY;
  relocation: PIMAGE_BASE_RELOCATION;
  dest: Pointer;
  relInfo: {PUINT16}PWORD;
  patchAddrHL: PDWORD;
//  {$IFDEF CPUX64}
  patchAddr64: PULONGLONG;
//  {$ENDIF}
  relType, offset: Integer;
begin
  codebase := module.codeBase;
  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_BASERELOC );
  if directory.Size = 0 then
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit( delta = 0 );
    {$ELSE}
    begin
    result := delta = 0;
    Exit;
    end;
    {$IFEND}

  {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
  relocation := PIMAGE_BASE_RELOCATION( PByte( codebase ) + directory.VirtualAddress );
  {$ELSE}
  relocation := PIMAGE_BASE_RELOCATION( PAnsiChar( codebase ) + directory.VirtualAddress );
  {$IFEND}

  while relocation.VirtualAddress > 0 do
    begin
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    dest    := Pointer( PByte( codebase ) + relocation.VirtualAddress );
    relInfo := Pointer( PByte( relocation ) + IMAGE_SIZEOF_BASE_RELOCATION );
    {$ELSE}
    dest    := Pointer( PAnsiChar( codebase ) + relocation.VirtualAddress );
    relInfo := Pointer( PAnsiChar( relocation ) + IMAGE_SIZEOF_BASE_RELOCATION );
    {$IFEND}

    for i := 0 to Trunc( ( ( relocation.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION ) / 2 ) ) - 1 do
      begin
      // the upper 4 bits define the type of relocation
      relType := relInfo^ shr 12;
      // the lower 12 bits define the offset
      offset := relInfo^ and $FFF;

      case relType of
        IMAGE_REL_BASED_ABSOLUTE: ; // skip relocation
        IMAGE_REL_BASED_HIGHLOW:
          begin
          // change complete 32 bit address
          {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
          patchAddrHL := Pointer( PByte( dest ) + offset );
          {$ELSE}
          patchAddrHL := Pointer( PAnsiChar( dest ) + offset );
          {$IFEND}

          {$IFOPT R+}
            {$DEFINE RANGECHECK_REENABLE}
            {$RANGECHECKS OFF} // {$R-}
          {$ENDIF}
          patchAddrHL^ := patchAddrHL^+delta;
          {$IFDEF RANGECHECK_REENABLE}
            {$RANGECHECKS ON} // {$R+}
            {$UNDEF RANGECHECK_REENABLE}
          {$ENDIF}
          end;
//        {$IFDEF CPUX64}
        IMAGE_REL_BASED_DIR64:
          begin
          if module.headers.X64 then
            begin
            {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
            patchAddr64 := Pointer( PByte( dest ) + offset );
            {$ELSE}
            patchAddr64 := Pointer( PAnsiChar( dest ) + offset );
            {$IFEND}
//            Inc( patchAddr64^, delta );
            patchAddr64^ := Int64( patchAddr64^ )+delta;
            end;
          end;
//        {$ENDIF}
      end;

      Inc( relInfo );
      end; // for

    // advance to next relocation block
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    relocation := PIMAGE_BASE_RELOCATION( PByte( relocation ) + relocation.SizeOfBlock );
    {$ELSE}
    relocation := PIMAGE_BASE_RELOCATION( PAnsiChar( relocation ) + relocation.SizeOfBlock );
    {$IFEND}
    end; // while

  Result := True;
end;

{$IFDEF MEMORY_DEPENDENCIES}
// Implemented further below (after ModuleManager / MemoryLoadLibrary are declared).
function ResolveMemoryDependency( const AName : string ) : PMemoryModule; forward;
function MemoryGetProcAddressByOrdinal( module : PMemoryModule; ordinal : Word ) : Pointer; forward;
{$ENDIF MEMORY_DEPENDENCIES}

function BuildImportTable( module: PMemoryModule ): Boolean; stdcall;
var
  codebase: Pointer;
  directory: PIMAGE_DATA_DIRECTORY;
  importDesc: PIMAGE_IMPORT_DESCRIPTOR;
  thunkRef: PUINT_PTR;
  funcRef: ^FARPROC;
  handle: HMODULE;
  thunkData: PIMAGE_IMPORT_BY_NAME;
  vName : PAnsiChar;
  {$IFDEF GetModuleHandle_BuildImportTable}
  vFree : Boolean;
  {$ENDIF GetModuleHandle_BuildImportTable}
  {$IFDEF MEMORY_DEPENDENCIES}
  depMem : PMemoryModule;
  {$ENDIF MEMORY_DEPENDENCIES}
begin
  codebase := module.codeBase;
  Result := True;

  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_IMPORT );
  if directory.Size = 0 then
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit( True );
    {$ELSE}
    begin
    result := True;
    Exit;
    end;
    {$IFEND}

  {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
  importDesc := PIMAGE_IMPORT_DESCRIPTOR( PByte( codebase ) + directory.VirtualAddress );
  {$ELSE}
  importDesc := PIMAGE_IMPORT_DESCRIPTOR( PAnsiChar( codebase ) + directory.VirtualAddress );
  {$IFEND}

  while ( not IsBadReadPtr( importDesc, SizeOf( IMAGE_IMPORT_DESCRIPTOR ) ) ) and ( importDesc.Name <> 0 ) do
    begin
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    vName := PAnsiChar( PByte( codebase ) + importDesc.Name );
    {$ELSE}
    vName := PAnsiChar( PAnsiChar( codebase ) + importDesc.Name );
    {$IFEND}

    {$IFDEF MEMORY_DEPENDENCIES}
    depMem := ResolveMemoryDependency( string( AnsiString( vName ) ) );
    if Assigned( depMem ) then
      begin
      handle := 0; // memory dependency: no real HMODULE, freed via the ModuleManager
      {$IFDEF GetModuleHandle_BuildImportTable}
      vFree := False;
      {$ENDIF GetModuleHandle_BuildImportTable}
      end
    else
    {$ENDIF MEMORY_DEPENDENCIES}
      begin
      {$IFDEF GetModuleHandle_BuildImportTable}
      handle := GetModuleHandleA( vName );
      vFree := ( handle = 0 );
      if vFree then
      {$ENDIF GetModuleHandle_BuildImportTable}
        handle := LoadLibraryA_Internal( vName );
      end;

    if ( handle = 0 ){$IFDEF MEMORY_DEPENDENCIES} AND ( NOT Assigned( depMem ) ){$ENDIF} then
      begin
      SetLastError( ERROR_MOD_NOT_FOUND );
      Result := False;
      Break;
      end;

    try
      {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
      UnregisterLeakBlock( DynArrayBlockBase( Pointer( module.modules ) ) );
      {$IFEND}
      SetLength( module.modules, Length( module.modules )+1 );
      {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
      RegisterLeakBlock( DynArrayBlockBase( Pointer( module.modules ) ) );
      {$IFEND}
    except
      {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
      RegisterLeakBlock( DynArrayBlockBase( Pointer( module.modules ) ) );
      {$IFEND}
      FreeLibrary_Internal( handle );
      SetLastError( ERROR_OUTOFMEMORY );
      Result := False;
      Break;
    end;
    module.modules[ High( module.Modules ) ].Handle := handle;
    {$IFDEF GetModuleHandle_BuildImportTable}
    module.modules[ High( module.Modules ) ].Free   := vFree;
    {$ENDIF GetModuleHandle_BuildImportTable}

    if importDesc.OriginalFirstThunk <> 0 then
      begin
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      thunkRef := Pointer( PByte( codebase ) + importDesc.OriginalFirstThunk );
      funcRef := Pointer( PByte( codebase ) + importDesc.FirstThunk );
      {$ELSE}
      thunkRef := Pointer( PAnsiChar( codebase ) + importDesc.OriginalFirstThunk );
      funcRef := Pointer( PAnsiChar( codebase ) + importDesc.FirstThunk );
      {$IFEND}
      end
    else
      begin
      // no hint table
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      thunkRef := Pointer( PByte( codebase ) + importDesc.FirstThunk );
      funcRef := Pointer( PByte( codebase ) + importDesc.FirstThunk );
      {$ELSE}
      thunkRef := Pointer( PAnsiChar( codebase ) + importDesc.FirstThunk );
      funcRef := Pointer( PAnsiChar( codebase ) + importDesc.FirstThunk );
      {$IFEND}
      end;

    while thunkRef^ <> 0 do
      begin
      if ( module.headers.X64 AND IMAGE_SNAP_BY_ORDINAL64( thunkRef^ ) ) OR
         ( NOT module.headers.X64 AND IMAGE_SNAP_BY_ORDINAL32( thunkRef^ ) ) then
        begin
        {$IFDEF MEMORY_DEPENDENCIES}
        if Assigned( depMem ) then
          funcRef^ := MemoryGetProcAddressByOrdinal( depMem, IMAGE_ORDINAL( thunkRef^ ) )
        else
        {$ENDIF MEMORY_DEPENDENCIES}
          funcRef^ := GetProcAddress_Internal( handle, PAnsiChar( IMAGE_ORDINAL( thunkRef^ ) ) );
        end
      else
        begin
        {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
        thunkData := PIMAGE_IMPORT_BY_NAME( PByte( codebase ) + thunkRef^ );
        {$ELSE}
        thunkData := PIMAGE_IMPORT_BY_NAME( PAnsiChar( codebase ) + thunkRef^ ); // RangeCheck causing Internal-Error C1118
        {$IFEND}
        {$IFDEF MEMORY_DEPENDENCIES}
        if Assigned( depMem ) then
          funcRef^ := MemoryGetProcAddress( depMem, PAnsiChar( @( thunkData.Name ) ) )
        else
        {$ENDIF MEMORY_DEPENDENCIES}
          funcRef^ := GetProcAddress_Internal( handle, PAnsiChar( @( thunkData.Name ) ) );
        end;
      if funcRef^ = nil then
        begin
        Result := False;
        Break;
        end;
      Inc( funcRef );
      Inc( thunkRef );
      end; // while

    if not Result then
      begin
      FreeLibrary_Internal( handle );
      SetLastError( ERROR_PROC_NOT_FOUND );
      Break;
      end;

    Inc( importDesc );
    end; // while
end;

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{$IFDEF GetModuleHandle}
type
  tModuleManager = class
  private
    fItems : Array of packed record
                      Handle     : PMemoryModule;
                      Data       : Pointer;
                      {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
                      FileName   : string;
                      {$IFEND}
                      {$IFDEF LOAD_FROM_RESOURCE}
                      IsResource : Boolean;
                      {$ENDIF LOAD_FROM_RESOURCE}

                      {$IFDEF UnloadAllOnFinalize}
                      DontUnload : Boolean;
                      {$ENDIF UnloadAllOnFinalize}
                      end;
    {$IFDEF GetModuleHandleCriticalSection}
    fCrit  : TCriticalSection;
    {$ENDIF GetModuleHandleCriticalSection}
    {$IFDEF MEMORY_DEPENDENCIES}
    fData    : Array of record
                        Name    : string;   // module name, e.g. 'SDL3.dll'
                        ResName : string;    // resource name (empty if buffer-based)
                        Data    : Pointer;   // raw PE bytes (nil if resource-based)
                        Size    : NativeUInt;
                        Loaded  : PMemoryModule; // module once loaded, so shared deps load only once
                        end;
    fLoading : Array of string; // names currently being resolved (circular-dependency guard)
    {$ENDIF MEMORY_DEPENDENCIES}
    procedure   DelID( ID : Word );
    function    GetHandle( Data : Pointer ) : PMemoryModule; {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}overload;{$IFEND}
    {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
    function    GetHandle_( Name : String ) : PMemoryModule;
    function    GetName( Handle : PMemoryModule ) : String;
    {$IFEND Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
    {$IFDEF LOAD_FROM_RESOURCE}
    function    GetIsResource( Handle : PMemoryModule ) : boolean;
    {$ENDIF LOAD_FROM_RESOURCE}
    {$IFDEF UnloadAllOnFinalize}
    procedure   UnloadAll;
    {$ENDIF UnloadAllOnFinalize}
  public
    constructor Create; reintroduce;
    destructor  Destroy; override;
    procedure   Add( Handle : PMemoryModule; Data : Pointer{$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}; Name : String{$IFEND}{$IFDEF LOAD_FROM_RESOURCE}; IsResource : boolean{$ENDIF} );
    procedure   Del( Handle : PMemoryModule ); overload;
    procedure   DelData( Data : Pointer );
    {$IFDEF MEMORY_DEPENDENCIES}
    procedure   RegisterData( const Name : string; Data : Pointer; Size : NativeUInt ); overload;
    procedure   RegisterData( const Name, ResName : string ); overload;
    procedure   UnregisterData( const Name : string );
    function    FindData( const Name : string; out ResName : string; out Data : Pointer; out Size : NativeUInt ) : Boolean;
    function    GetDataHandle( const Name : string ) : PMemoryModule;
    procedure   SetDataHandle( const Name : string; Handle : PMemoryModule );
    procedure   ClearDataHandle( Handle : PMemoryModule );
    function    GetHandleByName( const Name : string ) : PMemoryModule;
    function    BeginLoad( const Name : string ) : Boolean;
    procedure   EndLoad( const Name : string );
    {$ENDIF MEMORY_DEPENDENCIES}
    {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
    procedure   Del( Name : String{$IFDEF LOAD_FROM_RESOURCE}; IsResource : boolean{$ENDIF} ); overload;
    {$IFEND Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
    {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
    function    GetHandle( Name : String{$IFDEF LOAD_FROM_RESOURCE}; IsResource : boolean{$ENDIF} ) : PMemoryModule; overload;
    {$IFEND Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
    property    ID[ Name : String ]        : PMemoryModule read GetHandle_;
    {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
    property    Name[ ID : PMemoryModule ] : string        read GetName;
    {$IFEND Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
    {$IFDEF LOAD_FROM_RESOURCE}
    property    IsResource[ ID : PMemoryModule ] : boolean read GetIsResource;
    {$ENDIF LOAD_FROM_RESOURCE}
  end;

var
  ModuleManager : tModuleManager = nil;
  {$IFDEF UnloadAllOnFinalize}
  InitializationDone : boolean = False;
  {$ENDIF UnloadAllOnFinalize}

constructor tModuleManager.Create;
begin
  inherited;
  SetLength( fItems, 0 );
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit := TCriticalSection.Create;
  {$ENDIF GetModuleHandleCriticalSection}

  {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
  {$if Declared( FastMM_RegisterExpectedMemoryLeak )}
  FastMM_RegisterExpectedMemoryLeak( Self );
  {$ELSE}
  RegisterExpectedMemoryLeak( Self );
  {$IFEND}
  {$IFEND}
end;

destructor tModuleManager.Destroy;
{$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
var
  i : Integer;
{$IFEND}
begin
  {$IFDEF UnloadAllOnFinalize}
  UnloadAll;
  {$ENDIF UnloadAllOnFinalize}
  {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
  {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
  for i := Low( fItems ) to High( fItems ) do
    UnregisterLeakBlock( StringBlockBase( Pointer( fItems[ i ].FileName ) ) );
  {$IFEND}
  UnregisterLeakBlock( DynArrayBlockBase( Pointer( fItems ) ) );
  {$IFEND}
  SetLength( fItems, 0 );
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Free;
  {$ENDIF GetModuleHandleCriticalSection}
  inherited;
end;

procedure tModuleManager.Add( Handle : PMemoryModule; Data : Pointer{$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}; Name : String{$IFEND}{$IFDEF LOAD_FROM_RESOURCE}; IsResource : boolean{$ENDIF} );
var
  i : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  if NOT Assigned( Handle ) then
    Exit;
//  if ( Name = '' ) then
//    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := Low( fItems ) to High( fItems ) do
    begin
    if ( fItems[ i ].Handle = Handle ) then
      begin
      // Always overwrite Data, matching the insert branch below - previously this only happened
      // when IsResource, so a second Add() for the same Handle with Data=nil (MemoryLoadLibraryFile
      // re-Add'ing under the real FileName, after MemoryLoadLibrary's own internal Add already stored
      // the temporary read buffer's address) silently kept that now-freed buffer pointer around
      // forever instead of clearing it. Harmless on its own, but MEMORY_REFCOUNT's identity lookup
      // (ModuleManager.GetHandle(Data)) would then be one heap-reuse away from matching a stale
      // pointer and returning the wrong module.
      fItems[ i ].Data       := Data;
      {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
      {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
      UnregisterLeakBlock( StringBlockBase( Pointer( fItems[ i ].FileName ) ) );
      {$IFEND}
      fItems[ i ].FileName   := Name;
      {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
      UniqueString( fItems[ i ].FileName ); // sole ownership, so the expected leak registration tracks this block
      RegisterLeakBlock( StringBlockBase( Pointer( fItems[ i ].FileName ) ) );
      {$IFEND}
      {$IFEND}
      {$IFDEF LOAD_FROM_RESOURCE}
      fItems[ i ].IsResource := IsResource;
      {$ENDIF LOAD_FROM_RESOURCE}

      {$IFDEF GetModuleHandleCriticalSection}
      fCrit.Leave;
      {$ENDIF GetModuleHandleCriticalSection}
      Exit;
      end;
    end;

  {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
  UnregisterLeakBlock( DynArrayBlockBase( Pointer( fItems ) ) );
  {$IFEND}
  SetLength( fItems, Length( fItems )+1 );
  {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
  RegisterLeakBlock( DynArrayBlockBase( Pointer( fItems ) ) );
  {$IFEND}
  fItems[ High( fItems ) ].Handle   := Handle;
  fItems[ High( fItems ) ].Data     := Data;
  {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
  fItems[ High( fItems ) ].FileName := Name;
  {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
  UniqueString( fItems[ High( fItems ) ].FileName ); // sole ownership, so the expected leak registration tracks this block
  RegisterLeakBlock( StringBlockBase( Pointer( fItems[ High( fItems ) ].FileName ) ) );
  {$IFEND}
  {$IFEND}
  {$IFDEF LOAD_FROM_RESOURCE}
  fItems[ High( fItems ) ].IsResource := IsResource;
  {$ENDIF LOAD_FROM_RESOURCE}
  {$IFDEF UnloadAllOnFinalize}
  fItems[ High( fItems ) ].DontUnload := NOT InitializationDone;
  {$ENDIF UnloadAllOnFinalize}
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;

procedure tModuleManager.DelID( ID : Word );
var
  i : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  if ( ID > High( fItems ) ) then
    Exit;
//  {$IFDEF GetModuleHandleCriticalSection}
//  fCrit.Enter;
//  {$ENDIF GetModuleHandleCriticalSection}
  {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
  {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
  UnregisterLeakBlock( StringBlockBase( Pointer( fItems[ ID ].FileName ) ) ); // freed by the shift below
  {$IFEND}
  UnregisterLeakBlock( DynArrayBlockBase( Pointer( fItems ) ) );
  {$IFEND}
  for i := ID to High( fItems )-1 do
    fItems[ i ] := fItems[ i+1 ];
    SetLength( fItems, Length( fItems )-1 );
  {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
  RegisterLeakBlock( DynArrayBlockBase( Pointer( fItems ) ) );
  {$IFEND}
//  {$IFDEF GetModuleHandleCriticalSection}
//  fCrit.Leave;
//  {$ENDIF GetModuleHandleCriticalSection}
end;

procedure tModuleManager.Del( Handle : PMemoryModule );
var
  i : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  if NOT Assigned( Handle ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := High( fItems ) downTo Low( fItems ) do
    begin
    if ( fItems[ i ].Handle = Handle ) then
      begin
      DelID( i );
      break;
      end;
    end;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;

procedure tModuleManager.DelData( Data : Pointer );
var
  i : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  if NOT Assigned( Data ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := High( fItems ) downTo Low( fItems ) do
    begin
    if ( fItems[ i ].Data = Data ) then
      begin
      DelID( i );
//      break;
      end;
    end;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;

{$IFDEF UnloadAllOnFinalize}
procedure tModuleManager.UnloadAll;
var
  i : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := High( fItems ) downTo Low( fItems ) do
    begin
    {$IFDEF UnloadAllOnFinalize}
    if NOT fItems[ i ].DontUnload then
    {$ENDIF UnloadAllOnFinalize}
      begin
      {$IFDEF MEMORY_REFCOUNT}
      // Everything is coming down regardless of how many callers were still sharing this module -
      // force the single MemoryFreeLibrary call below to actually tear it down, not just decrement.
      if Assigned( fItems[ i ].Handle ) then
        fItems[ i ].Handle.refCount := 1;
      {$ENDIF MEMORY_REFCOUNT}
      MemoryFreeLibrary( fItems[ i ].Handle );
      end;
    end;
  SetLength( fItems, 0 );    
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;
{$ENDIF UnloadAllOnFinalize}

function tModuleManager.GetHandle( Data : Pointer ) : PMemoryModule;
var
  i : Integer;
begin
  result := nil;
  if NOT Assigned( self ) then
    Exit;
  if NOT Assigned( Data ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := Low( fItems ) to High( fItems ) do
    begin
    if ( fItems[ i ].Data = Data ) then
      begin
      result := fItems[ i ].Handle;
      break;
      end;
    end;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;

{$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
procedure tModuleManager.Del( Name : String{$IFDEF LOAD_FROM_RESOURCE}; IsResource : boolean{$ENDIF} );
var
  i : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
//  if ( Name = '' ) then
//    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := High( fItems ) downTo Low( fItems ) do
    begin
    if ( CompareString( LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar( fItems[ i ].FileName ), Length( fItems[ i ].FileName ), PChar( Name ), Length( Name ) ) = 2 )
        {$IFDEF LOAD_FROM_RESOURCE}AND ( fItems[ i ].IsResource = IsResource ){$ENDIF} then
      begin
      DelID( i );
//      break;
      end;
    end;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;

function tModuleManager.GetHandle_( Name : String ) : PMemoryModule;
begin
  result := GetHandle( Name{$IFDEF LOAD_FROM_RESOURCE}, False{IsResource}{$ENDIF} );
end;

function tModuleManager.GetHandle( Name : String{$IFDEF LOAD_FROM_RESOURCE}; IsResource : boolean{$ENDIF} ) : PMemoryModule;
var
  i : Integer;
begin
  result := nil;
  if NOT Assigned( self ) then
    Exit;
  if ( Name = '' ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := Low( fItems ) to High( fItems ) do
    begin
    if ( CompareString( LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar( fItems[ i ].FileName ), Length( fItems[ i ].FileName ), PChar( Name ), Length( Name ) ) = 2 )
        {$IFDEF LOAD_FROM_RESOURCE}AND ( fItems[ i ].IsResource = IsResource ){$ENDIF} then
      begin
      result := fItems[ i ].Handle;
      break;
      end;
    end;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;

function tModuleManager.GetName( Handle : PMemoryModule ) : String;
var
  i : Integer;
begin
  result := '';
  if NOT Assigned( self ) then
    Exit;
  if NOT Assigned( Handle ) then
    Exit;
//  if ( Name = '' ) then
//    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := Low( fItems ) to High( fItems ) do
    begin
    if ( fItems[ i ].Handle = Handle ) then
      begin
      result := fItems[ i ].FileName;
      break;
      end;
    end;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;
{$IFEND Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}

{$IFDEF LOAD_FROM_RESOURCE}
function tModuleManager.GetIsResource( Handle : PMemoryModule ) : boolean;
var
  i : Integer;
begin
  result := False;
  if NOT Assigned( self ) then
    Exit;
  if NOT Assigned( Handle ) then
    Exit;
//  if ( Name = '' ) then
//    Exit;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Enter;
  {$ENDIF GetModuleHandleCriticalSection}
  for i := Low( fItems ) to High( fItems ) do
    begin
    if ( fItems[ i ].Handle = Handle ) then
      begin
      result := fItems[ i ].IsResource;
      break;
      end;
    end;
  {$IFDEF GetModuleHandleCriticalSection}
  fCrit.Leave;
  {$ENDIF GetModuleHandleCriticalSection}
end;
{$ENDIF LOAD_FROM_RESOURCE}

{$IFDEF MEMORY_DEPENDENCIES}
procedure tModuleManager.RegisterData( const Name : string; Data : Pointer; Size : NativeUInt );
var
  i, n : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  if ( Name = '' ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  n := -1;
  for i := Low( fData ) to High( fData ) do
    if SameModuleName( fData[ i ].Name, Name ) then
      begin n := i; Break; end;
  if ( n < 0 ) then
    begin
    SetLength( fData, Length( fData )+1 );
    n := High( fData );
    end;
  fData[ n ].Name    := Name;
  fData[ n ].ResName := '';
  fData[ n ].Data    := Data;
  fData[ n ].Size    := Size;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

procedure tModuleManager.RegisterData( const Name, ResName : string );
var
  i, n : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  if ( Name = '' ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  n := -1;
  for i := Low( fData ) to High( fData ) do
    if SameModuleName( fData[ i ].Name, Name ) then
      begin n := i; Break; end;
  if ( n < 0 ) then
    begin
    SetLength( fData, Length( fData )+1 );
    n := High( fData );
    end;
  fData[ n ].Name    := Name;
  fData[ n ].ResName := ResName;
  fData[ n ].Data    := nil;
  fData[ n ].Size    := 0;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

procedure tModuleManager.UnregisterData( const Name : string );
var
  i, j : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  for i := High( fData ) downTo Low( fData ) do
    if SameModuleName( fData[ i ].Name, Name ) then
      begin
      for j := i to High( fData )-1 do
        fData[ j ] := fData[ j+1 ];
      SetLength( fData, Length( fData )-1 );
      end;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

function tModuleManager.FindData( const Name : string; out ResName : string; out Data : Pointer; out Size : NativeUInt ) : Boolean;
var
  i : Integer;
begin
  Result  := False;
  ResName := '';
  Data    := nil;
  Size    := 0;
  if NOT Assigned( self ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  for i := Low( fData ) to High( fData ) do
    if SameModuleName( fData[ i ].Name, Name ) then
      begin
      ResName := fData[ i ].ResName;
      Data    := fData[ i ].Data;
      Size    := fData[ i ].Size;
      Result  := True;
      Break;
      end;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

// Returns the module a registered dependency was already loaded into (nil if not loaded yet).
// This is what makes a dependency shared by several importers load only once, even when its
// resource name differs from its module name.
function tModuleManager.GetDataHandle( const Name : string ) : PMemoryModule;
var
  i : Integer;
begin
  Result := nil;
  if NOT Assigned( self ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  for i := Low( fData ) to High( fData ) do
    if SameModuleName( fData[ i ].Name, Name ) then
      begin
      Result := fData[ i ].Loaded;
      Break;
      end;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

// Remembers which module a dependency was loaded into. Creates an entry when the dependency was
// found by the resource-name convention rather than by explicit registration.
procedure tModuleManager.SetDataHandle( const Name : string; Handle : PMemoryModule );
var
  i, n : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  if ( Name = '' ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  n := -1;
  for i := Low( fData ) to High( fData ) do
    if SameModuleName( fData[ i ].Name, Name ) then
      begin n := i; Break; end;
  if ( n < 0 ) then
    begin
    SetLength( fData, Length( fData )+1 );
    n := High( fData );
    fData[ n ].Name    := Name;
    fData[ n ].ResName := '';
    fData[ n ].Data    := nil;
    fData[ n ].Size    := 0;
    end;
  fData[ n ].Loaded := Handle;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

// Invalidates cached module pointers when a module is freed, so a later import reloads it
// instead of handing out a dangling pointer.
procedure tModuleManager.ClearDataHandle( Handle : PMemoryModule );
var
  i : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  if NOT Assigned( Handle ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  for i := Low( fData ) to High( fData ) do
    if ( fData[ i ].Loaded = Handle ) then
      fData[ i ].Loaded := nil;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

function tModuleManager.GetHandleByName( const Name : string ) : PMemoryModule;
var
  i : Integer;
begin
  Result := nil;
  if NOT Assigned( self ) then
    Exit;
  if ( Name = '' ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  for i := Low( fItems ) to High( fItems ) do
    if SameModuleName( fItems[ i ].FileName, Name ) then
      begin
      Result := fItems[ i ].Handle;
      Break;
      end;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

function tModuleManager.BeginLoad( const Name : string ) : Boolean;
var
  i : Integer;
begin
  Result := False;
  if NOT Assigned( self ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  for i := Low( fLoading ) to High( fLoading ) do
    if SameModuleName( fLoading[ i ], Name ) then
      begin
      {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
      Exit; // already being resolved -> circular dependency
      end;
  SetLength( fLoading, Length( fLoading )+1 );
  fLoading[ High( fLoading ) ] := Name;
  Result := True;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;

procedure tModuleManager.EndLoad( const Name : string );
var
  i, j : Integer;
begin
  if NOT Assigned( self ) then
    Exit;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Enter;{$ENDIF}
  for i := High( fLoading ) downTo Low( fLoading ) do
    if SameModuleName( fLoading[ i ], Name ) then
      begin
      for j := i to High( fLoading )-1 do
        fLoading[ j ] := fLoading[ j+1 ];
      SetLength( fLoading, Length( fLoading )-1 );
      Break;
      end;
  {$IFDEF GetModuleHandleCriticalSection}fCrit.Leave;{$ENDIF}
end;
{$ENDIF MEMORY_DEPENDENCIES}

{$ENDIF GetModuleHandle}

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***  Memory DLL loading functions Implementation  ***
    ----------------------------------------------------- }
function MemoryLoadLibrary_1( data: Pointer; var Code : Pointer; var Module : PMemoryModule; Flags : Cardinal = 0 ) : ShortInt; stdcall;
var
  dos_header: PIMAGE_DOS_HEADER;
  old_header: PIMAGE_NT_HEADERS32;
//  code,
  headers: Pointer;
  P, P2 : PByte;
  locationdelta: Int64; // NativeInt;
  sysInfo: SYSTEM_INFO;
begin
  Result := -9;
  if NOT Assigned( Data ) then
    Exit;
  Result := -8;
  module := nil;

  try
    dos_header := PIMAGE_DOS_HEADER( data );
    if ( dos_header.e_magic <> IMAGE_DOS_SIGNATURE ) then
      begin
      Result := -7;
      SetLastError( ERROR_BAD_EXE_FORMAT );
      Exit;
      end;

    // old_header = ( PIMAGE_NT_HEADERS )&( ( const unsigned char * )( data ) )[ dos_header->e_lfanew ];
    old_header := PIMAGE_NT_HEADERS32( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( data ) + dos_header._lfanew );
    if old_header.Signature <> IMAGE_NT_SIGNATURE then
      begin
      Result := -6;
      SetLastError( ERROR_BAD_EXE_FORMAT );
      Exit;
      end;

    if ( ( LOAD_LIBRARY_AS_DATAFILE           AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE ) AND
       ( ( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE ) AND
       ( ( DONT_RESOLVE_DLL_REFERENCES        AND Flags ) <> DONT_RESOLVE_DLL_REFERENCES ) AND
       ( ( LOAD_LIBRARY_AS_IMAGE_RESOURCE     AND Flags ) <> LOAD_LIBRARY_AS_IMAGE_RESOURCE ) then
      begin
      {$IFDEF CPUX64}
      if ( old_header.FileHeader.Machine <> IMAGE_FILE_MACHINE_AMD64 ) then
      {$ELSE}
      if ( old_header.FileHeader.Machine <> IMAGE_FILE_MACHINE_I386 ) then
      {$ENDIF}
        begin
        Result := -5;
        SetLastError( ERROR_BAD_EXE_FORMAT );
        Exit;
        end;
      end
    else
      begin
      if ( old_header.FileHeader.Machine <> IMAGE_FILE_MACHINE_AMD64 ) AND
         ( old_header.FileHeader.Machine <> IMAGE_FILE_MACHINE_I386 ) then
        begin
        Result := -5;
        SetLastError( ERROR_BAD_EXE_FORMAT );
        Exit;
        end;
      end;

    if ( old_header.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64 ) then
      begin
      if ( PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SectionAlignment and 1 ) <> 0 then
        begin
        // Only support section alignments that are a multiple of 2
        Result := -4;
        SetLastError( ERROR_BAD_EXE_FORMAT );
        Exit;
        end;

      // reserve memory for image of library
      // XXX: is it correct to commit the complete memory region at once?
      //      calling DllEntry raises an exception if we don't...
      code := VirtualAlloc( Pointer( PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.ImageBase ),
                           PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfImage,
                           MEM_RESERVE or MEM_COMMIT,
                           PAGE_READWRITE );

      if code = nil then
        begin
        // try to allocate memory at arbitrary position
        code := VirtualAlloc( nil,
                             PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfImage,
                             MEM_RESERVE or MEM_COMMIT,
                             PAGE_READWRITE );
        if code = nil then
          begin
          Result := -3;
          SetLastError( ERROR_OUTOFMEMORY );
          Exit;
          end;
        end;
      end
    else
      begin
      if ( old_header.OptionalHeader.SectionAlignment and 1 ) <> 0 then
        begin
        // Only support section alignments that are a multiple of 2
        Result := -4;
        SetLastError( ERROR_BAD_EXE_FORMAT );
        Exit;
        end;

      // reserve memory for image of library
      // XXX: is it correct to commit the complete memory region at once?
      //      calling DllEntry raises an exception if we don't...
      code := VirtualAlloc( Pointer( old_header.OptionalHeader.ImageBase ),
                           old_header.OptionalHeader.SizeOfImage,
                           MEM_RESERVE or MEM_COMMIT,
                           PAGE_READWRITE );

      if code = nil then
        begin
        // try to allocate memory at arbitrary position
        code := VirtualAlloc( nil,
                             old_header.OptionalHeader.SizeOfImage,
                             MEM_RESERVE or MEM_COMMIT,
                             PAGE_READWRITE );
        if code = nil then
          begin
          Result := -3;
          SetLastError( ERROR_OUTOFMEMORY );
          Exit;
          end;
        end;
      end;

    module := PMemoryModule( HeapAlloc( GetProcessHeap, HEAP_ZERO_MEMORY, SizeOf( TMemoryModule ) ) );
    if module = nil then
      begin
      VirtualFree( code, 0, MEM_RELEASE );
      Result := -2;
      SetLastError( ERROR_OUTOFMEMORY );
      Exit;
      end;

    // memory is zeroed by HeapAlloc
    module.codeBase := code;
    GetNativeSystemInfo( {$IF ( CompilerVersion < 23 ) OR Defined( FPC )}@{$IFEND}sysInfo );
    module.pageSize := sysInfo.dwPageSize;

    if ( old_header.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64 ) then
      begin
      // commit memory for headers
      headers := VirtualAlloc( code, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE );

      // copy PE header to code
      CopyMemory( headers, dos_header, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfHeaders );
      end
    else
      begin
      // commit memory for headers
      headers := VirtualAlloc( code, old_header.OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE );

      // copy PE header to code
      CopyMemory( headers, dos_header, old_header.OptionalHeader.SizeOfHeaders );
      end;

    // result->headers = ( PIMAGE_NT_HEADERS )&( ( const unsigned char * )( headers ) )[ dos_header->e_lfanew ];
    Module.headers.X64       := ( old_header.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64 );
    module.headers.headers32 := PIMAGE_NT_HEADERS32( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( headers ) + dos_header._lfanew );

    if ( ( LOAD_LIBRARY_AS_DATAFILE           AND Flags ) = LOAD_LIBRARY_AS_DATAFILE ) OR
       ( ( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE AND Flags ) = LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE ) then
      begin
      module^.isRelocated := False;
      P := headers;
      P2 := data;
      if ( old_header.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64 ) then
        begin
        Inc( P, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfHeaders );
        Inc( P2, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfHeaders );
        CopyMemory( P, P2, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfCode );
        Inc( P, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfCode );
        Inc( P2, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfCode );
        CopyMemory( P, P2, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfInitializedData );
        Inc( P, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfInitializedData );
        Inc( P2, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfInitializedData );
        CopyMemory( P, P2, PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.SizeOfUninitializedData );
        end
      else
        begin
        Inc( P, old_header.OptionalHeader.SizeOfHeaders );
        Inc( P2, old_header.OptionalHeader.SizeOfHeaders );
        CopyMemory( P, P2, old_header.OptionalHeader.SizeOfCode );
        Inc( P, old_header.OptionalHeader.SizeOfCode );
        Inc( P2, old_header.OptionalHeader.SizeOfCode );
        CopyMemory( P, P2, old_header.OptionalHeader.SizeOfInitializedData );
        Inc( P, old_header.OptionalHeader.SizeOfInitializedData );
        Inc( P2, old_header.OptionalHeader.SizeOfInitializedData );
        CopyMemory( P, P2, old_header.OptionalHeader.SizeOfUninitializedData );
        end;

      result := 0;
      Exit;
      end;

    // copy sections from DLL file block to new memory location
    if not CopySections( data, old_header, module ) then
      begin
      Result := -1;
      SetLastError( ERROR_BAD_FORMAT );
      MemoryFreeLibrary( module );
      Exit;
      end;

    // adjust base address of imported data
    if ( old_header.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64 ) then
      locationdelta := Int64( code ) - Int64( PIMAGE_NT_HEADERS64( old_header ).OptionalHeader.ImageBase )
    else
      locationdelta := Int64( code ) - Int64( old_header.OptionalHeader.ImageBase );

    if locationdelta <> 0 then
      module.isRelocated := PerformBaseRelocation( module, locationdelta )
    else
      module.isRelocated := True;

    result := 0;
  except
    // cleanup
    MemoryFreeLibrary( module );
    Exit;
  end;
end;

{$IFDEF MANIFEST}
{$IF NOT DECLARED( tagACTCTXA )}
{$DEFINE ActCtx_NeedsInit}
type
  PULONG_PTR = PULONG;
var
  CreateActCtx     : function( ActCtx: Pointer{PACTCTX} ): THandle; stdcall;
  ReleaseActCtx    : procedure( hActCtx: THandle ); stdcall;
  ActivateActCtx   : function( hActCtx: THandle; lpCookie: PULONG_PTR ): BOOL; stdcall;
  DeactivateActCtx : function( dwFlags: DWORD; ulCookie: THandle ): BOOL; stdcall;
{$IFEND}
// Loading from HMODULE only works for FULLY initialized Modules
// LOAD_LIBRARY_AS_DATAFILE isnt sufficient
function LoadManifest( Module : THandle; var hActCtx : THandle; Cookie : PULONG_PTR; TempFile : boolean = True ) : boolean;
  {$IF NOT DECLARED(tagACTCTXA)}
  const
    ACTCTX_FLAG_RESOURCE_NAME_VALID           = $00000008;
    ACTCTX_FLAG_HMODULE_VALID                 = $00000080;
  type
    tagACTCTXA = record
      cbSize: ULONG;
      dwFlags: DWORD;
      lpSource: LPCSTR;
      wProcessorArchitecture: WORD;
      wLangId: LANGID;
      lpAssemblyDirectory: LPCSTR;
      lpResourceName: LPCSTR;
      lpApplicationName: LPCSTR;
      hModule: HMODULE;
    end;
    tagACTCTXW = record
      cbSize: ULONG;
      dwFlags: DWORD;
      lpSource: LPCWSTR;
      wProcessorArchitecture: WORD;
      wLangId: LANGID;
      lpAssemblyDirectory: LPCWSTR;
      lpResourceName: LPCWSTR;
      lpApplicationName: LPCWSTR;
      hModule: HMODULE;
    end;
    TActCtx = {$IFDEF UNICODE}tagACTCTXW{$ELSE}tagACTCTXA{$ENDIF};
    PActCtx = {$IFDEF UNICODE}^tagACTCTXW{$ELSE}^tagACTCTXA{$ENDIF};
  {$IFEND}

  function ExtractManifest( Module : HMODULE; FileName : string ) : boolean;
    function SetPrivilege( Privilege: PChar; EnablePrivilege: Boolean; out PreviousState: Boolean ): DWORD;
    var
      Token: THandle;
      NewState: TTokenPrivileges;
      Luid: TLargeInteger;
      PrevState: TTokenPrivileges;
      Return: DWORD;
    begin
      PreviousState := True;
      if ( GetVersion( ) > $80000000 ) then // Win9x 
        Result := ERROR_SUCCESS
      else
      begin // WinNT
        if not OpenProcessToken( GetCurrentProcess( ), MAXIMUM_ALLOWED, Token ) then
          Result := GetLastError( )
        else
        try
          if not LookupPrivilegeValue( nil, Privilege, Luid ) then
            Result := GetLastError( )
          else
          begin
            NewState.PrivilegeCount := 1;
            NewState.Privileges[0].Luid := Luid;
            if EnablePrivilege then
              NewState.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED
            else
              NewState.Privileges[0].Attributes := 0;
            if not AdjustTokenPrivileges( Token, False, NewState,
              SizeOf( TTokenPrivileges ), PrevState, Return ) then
              Result := GetLastError( )
            else
            begin
              Result := ERROR_SUCCESS;
              PreviousState := ( PrevState.Privileges[0].Attributes and SE_PRIVILEGE_ENABLED <> 0 );
            end;
          end;
        finally
          CloseHandle( Token );
        end;
      end;
    end;
  var
    HRes : HRSRC;
    HG   : HGlobal;
    f    : Textfile;
    S    : String;
    B    : Boolean;
  begin
    result := False;
    if ( Module = 0 ) OR ( Module = INVALID_HANDLE_VALUE ) then
      Exit;
    if ( FileName = '' ) then
      Exit;

    SetPrivilege( 'SeDebugPrivilege', True, B );
//    if IsExe( Module ) then
//      HRes := FindResource( Module, PChar( 1 ), PChar( 24 ){RT_MANIFEST} )
//    else
      HRes := FindResource( Module, PChar( 2 ), PChar( 24 ){RT_MANIFEST} );
    if ( HRes <> 0 ) then
      begin
      HG := LoadResource( Module, HRes );
      if HG = 0 then
        begin
        SetPrivilege( 'SeDebugPrivilege', B, B );
        Exit;
        end;
      try
        SetString( S, PAnsiChar( LockResource( HG ) ), SizeOfResource( Module, HRes ) );
      finally
        UnlockResource( HG );
        FreeResource( HG );
      end;

      try
        AssignFile( f, FileName );
        ReWrite( f );
        WriteLn( f, S );
        Flush( f );
        result := True;
      finally
        CloseFile( f );
      end;
      end;
    SetPrivilege( 'SeDebugPrivilege', B, B );
  end;
const
  TMP_MANIFEST = 'tmp.manifest';
var
  ActCtx : TActCtx;
{$IFDEF ActCtx_NeedsInit}
  tModule: THandle;
{$ENDIF ActCtx_NeedsInit}
begin
  result := false;
  hActCtx := INVALID_HANDLE_VALUE;
  if ( Cookie = nil ) then
    Exit;
  Cookie^ := 0;
  {$IFDEF ActCtx_NeedsInit}
  if NOT Assigned( CreateActCtx ) then
    begin
    tModule      := GetModuleHandle( kernel32 );
    CreateActCtx := GetProcAddress( tModule, 'CreateActCtx' + {$IFDEF UNICODE}'W'{$ELSE}'A'{$ENDIF} );
    if Assigned( CreateActCtx ) then
      begin
      ReleaseActCtx    := GetProcAddress( tModule, 'ReleaseActCtx' );
      ActivateActCtx   := GetProcAddress( tModule, 'ActivateActCtx' );
      DeactivateActCtx := GetProcAddress( tModule, 'DeactivateActCtx' );
      end
    else
      Exit;
    end;
  {$ENDIF}

  FillChar( ActCtx, SizeOf( ActCtx ), 0 );
  ActCtx.cbSize := SizeOf( ActCtx );
  if TempFile then
    begin
    if NOT ExtractManifest( Module, TMP_MANIFEST ) then
      Exit;
    ActCtx.dwFlags  := 0;
    actCtx.lpSource := TMP_MANIFEST;
    end
  else
    begin
    ActCtx.dwFlags        := ACTCTX_FLAG_RESOURCE_NAME_VALID or ACTCTX_FLAG_HMODULE_VALID;
    if ( Module = 0 ) OR ( Module = INVALID_HANDLE_VALUE ) then
      ActCtx.hModule      := HInstance
    else
      ActCtx.hModule      := Module;
//    if IsExe( Module ) then
//      ActCtx.lpResourceName := MakeIntResource( 1 )
//    else
      ActCtx.lpResourceName := MakeIntResource( 2 );
    end;

  SetLastError( ERROR_SUCCESS );
  hActCtx := CreateActCtx( @ActCtx );
  result := ( hActCtx <> INVALID_HANDLE_VALUE ) AND ActivateActCtx( hActCtx, Cookie );

  if TempFile then
    DeleteFile( TMP_MANIFEST );
end;

function UnloadManifest( hActCtx : THandle; Cookie : THandle ) : boolean;
begin
  result := ( Cookie = 0 ) AND ( ( hActCtx <> 0 ) OR ( hActCtx <> INVALID_HANDLE_VALUE ) );
  if ( Cookie <> 0 ) then
    result := DeactivateActCtx( 0, Cookie );

  if ( hActCtx <> INVALID_HANDLE_VALUE ) then
    ReleaseActCtx( hActCtx );
end;
{$ENDIF}

function MemoryLoadLibrary_2( var module: PMemoryModule ): ShortInt; stdcall;
{$IFDEF MANIFEST}
var
  hActCtx     : THandle;
  Cookie      : NativeUInt;
{$ENDIF}
begin
  result := -25;
  if NOT Assigned( Module ) then
    Exit;

  {$IFDEF MANIFEST}
  try
    LoadManifest( THandle( module^.codeBase ), hActCtx, @Cookie );
  except
  end;
  {$ENDIF}

  result := -24;
  try
    // load required dlls and adjust function table of imports
    if not BuildImportTable( module ) then
      begin
      result := -23;
      {$IFDEF MANIFEST}
      try
        UnloadManifest( hActCtx, Cookie );
      except
      end;
      {$ENDIF}
      SetLastError( ERROR_BAD_FORMAT );
      MemoryFreeLibrary( module );
      Exit;
      end;
  except
    // cleanup
    MemoryFreeLibrary( module );
    Exit;
  end;

  {$IFDEF MANIFEST}
  try
    UnloadManifest( hActCtx, Cookie );
  except
  end;
  {$ENDIF}

  result := -22;
  try
    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    if not FinalizeSections( module ) then
      begin
      result := -21;
      SetLastError( ERROR_BAD_FORMAT );
      MemoryFreeLibrary( module );
      Exit;
      end;
  except
    // cleanup
    MemoryFreeLibrary( module );
    Exit;
  end;

  result := 0;
end;

function MemoryLoadLibrary_3( var module: PMemoryModule; Code : Pointer ): ShortInt; stdcall;
var
  DllEntry    : TDllEntryProc;
  successfull : Boolean;
{$IF NOT Declared( SysUtils )}
  S           : string;
{$IFEND NOT Declared( SysUtils )}
begin
  result := -37;
  if NOT Assigned( Module ) then
    Exit;
  if NOT Assigned( Code ) then
    Exit;

  result := -36;
  try
    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    if not FinalizeSections( module ) then
      begin
      result := -35;
      SetLastError( ERROR_BAD_FORMAT );
      MemoryFreeLibrary( module );
      Exit;
      end;

    // Register unwind info BEFORE any module code runs, so exceptions raised in a TLS callback
    // or in DllMain can be unwound instead of tearing down the process.
    RegisterExceptionTable( module );
    {$IF Defined( MEMORY_SEH_X86 ) AND NOT Defined( CPUX64 )}
    RegisterInvertedFunctionTableEntry( module ); // x86: make SEH handlers in this module valid
    {$IFEND}
    {$IF Defined( MEMORY_FROM_ADDRESS_X64 ) AND Defined( CPUX64 )}
    RegisterInvertedFunctionTableEntryX64( module ); // x64: make FROM_ADDRESS/RtlPcToFileHeader find this module
    {$IFEND}

    {$IFDEF REGISTER_IN_PEB}
    // Same reasoning: on x86 the module must be known to the loader before its first try/except,
    // otherwise Windows discards the handler. The real name is filled in later by the caller.
    RegisterInPEB( module, Format_MemModuleName( module ) );
    {$IFDEF MEMORY_HANDLE_TLS}
    // Real dynamic TLS data: ask the loader to set up the module's TLS template before any code
    // of it runs (a TLS callback or DllMain may already touch threadvar).
    module.tlsHandled := MM_HandleTlsData( module );
    {$ENDIF MEMORY_HANDLE_TLS}
    {$ENDIF REGISTER_IN_PEB}

    // TLS callbacks are executed BEFORE the main loading
    ExecuteTLS( module );
//    if not ExecuteTLS( module ) then
//      begin
//      result := -34;
//      SetLastError( ERROR_BAD_FORMAT );
//      MemoryFreeLibrary( module );
//      Exit;
//      end;
  except
    // cleanup
    MemoryFreeLibrary( module );
    Exit;
  end;

  // get entry point of loaded library
  result := -33;
  if ( NOT module.headers.X64 AND ( module.headers.headers32.OptionalHeader.AddressOfEntryPoint <> 0 ) ) or // FIX: 32/64 were swapped
     ( module.headers.X64 AND ( module.headers.headers64.OptionalHeader.AddressOfEntryPoint <> 0 ) ) then
    begin
    if module.headers.X64 then
      @DllEntry := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( code ) + module.headers.headers64.OptionalHeader.AddressOfEntryPoint )
    else
      @DllEntry := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( code ) + module.headers.headers32.OptionalHeader.AddressOfEntryPoint );
//    successfull := false;
    try
      successfull := DllEntry( HINST( code ), DLL_PROCESS_ATTACH, nil ); // notify library about attaching to process
    except
    {$IF Declared( SysUtils )}
      on E : Exception do
        begin
        if ( E.ClassName = 'EExternalException' ) AND ( E.Message = 'External exception E06D7363' ) then // Win-SxS
          successfull := True
        else
          begin
          result := -32;
          MemoryFreeLibrary( module );
          Exit;
          end;
        end;
    {$ELSE}
      SetLength( S, 255 );
      SetLength( S, ExceptionErrorMessage( ExceptObject, ExceptAddr, PChar( S ), Length( S ) ) );
      if ( ExceptObject.ClassName = 'EExternalException' ) AND ( S = 'External exception E06D7363' ) then // Win-SxS
        successfull := True
      else
        begin
        result := -32;
        MemoryFreeLibrary( module );
        Exit;
        end;
    {$IFEND}
    end;

    if successfull then
      SetLastError( ERROR_SUCCESS )
    else
      begin
      result := -31;
      SetLastError( ERROR_DLL_INIT_FAILED );
      MemoryFreeLibrary( module );
      Exit;
      end;

    module.initialized := True;
    result := 0;
    end;
end;

function FileToPointer( lpFileStr: String; var Data : PByte; Flags : Cardinal = FILE_SHARE_DELETE OR FILE_SHARE_READ OR FILE_SHARE_WRITE ) : Cardinal;
var
  H   : THandle;
  Cnt : Cardinal;
begin
  result := 0;
  Data   := nil;
  if NOT FileExists( lpFileStr ) then
    Exit;

  H := CreateFile( PChar( lpFileStr ), GENERIC_READ, Flags, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
  if ( H = 0 ) OR ( H = INVALID_HANDLE_VALUE ) then
    Exit;

  result := GetFileSize( H, nil );
  GetMem( Data, result );
  if NOT ReadFile( H, Data^, result, Cnt, nil ) OR ( result <> Cnt ) then
    result := 0;
  CloseHandle( H );
end;

{$IFDEF ALLOW_LOAD_FILES}
function MemoryLoadLibraryFile( FileName : string; var Module : PMemoryModule; Flags : Cardinal = 0 ): ShortInt; stdcall;
var
  Data      : Pointer;
  Cnt       : Cardinal;
  SPPath    : String;
  pFileName : PChar;
begin
  result := -32;
  Module := nil;
  if NOT FileExists( FileName ) then
    begin
    // EnvironmentPath
    Cnt := SearchPath( nil{lpPath}, PChar( Filename ){lpFileName}, nil{lpExtension}, 0{nBufferLength}, nil{lpBuffer}, pFileName{lpFilePart} );
    if ( Cnt = 0 ) then
      Exit;
    SetLength( SPPath, Cnt-1 );
    if ( SearchPath( nil{lpPath}, PChar( Filename ){lpFileName}, nil{lpExtension}, Cnt, PChar( SPPath ){lpBuffer}, pFileName{lpFilePart} ) > 0 ) then
      FileName := SPPath;
    SetLength( SPPath, 0 );

    if NOT FileExists( FileName ) then
      Exit;
    end;

  {$IFDEF MEMORY_REFCOUNT}
  if Assigned( ModuleManager ) AND
     ( ( LOAD_LIBRARY_AS_DATAFILE           AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE ) AND
     ( ( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE ) AND
     ( ( DONT_RESOLVE_DLL_REFERENCES        AND Flags ) <> DONT_RESOLVE_DLL_REFERENCES ) AND
     ( ( LOAD_LIBRARY_AS_IMAGE_RESOURCE     AND Flags ) <> LOAD_LIBRARY_AS_IMAGE_RESOURCE ) then
    begin
    Module := ModuleManager.GetHandle( FileName{$IFDEF LOAD_FROM_RESOURCE}, False{IsResource}{$ENDIF} );
    if Assigned( Module ) then
      begin
      Inc( Module.refCount );
      result := 0;
      Exit;
      end;
    end;
  {$ENDIF MEMORY_REFCOUNT}

  Data := nil;
  FileToPointer( FileName, PByte( Data ) );
  if NOT Assigned( Data ) then
    begin
    result := -31;
    Exit;
    end;

  result := MemoryLoadLibrary( Data, Module, Flags );
  {$IFDEF GetModuleHandle}
  if ( ( LOAD_LIBRARY_AS_DATAFILE           AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE ) AND
     ( ( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE ) AND
     ( ( DONT_RESOLVE_DLL_REFERENCES    AND Flags ) <> DONT_RESOLVE_DLL_REFERENCES ) AND
     ( ( LOAD_LIBRARY_AS_IMAGE_RESOURCE AND Flags ) <> LOAD_LIBRARY_AS_IMAGE_RESOURCE ) AND ( result = 0 ) then
    begin
    ModuleManager.Add( Module, nil{Data}, FileName{$IFDEF LOAD_FROM_RESOURCE}, False{IsResource}{$ENDIF} );
    {$IFDEF MEMORY_REFCOUNT}
    Module.refCount := 1;
    {$ENDIF MEMORY_REFCOUNT}
    end;
  {$ENDIF GetModuleHandle}
  {$IFDEF REGISTER_IN_PEB}
  if ( result = 0 ) then
    UpdatePEBName( Module, FileName ); // real name for stack walkers
  {$ENDIF REGISTER_IN_PEB}
  FreeMem( Data );
end;
{$ENDIF}

{$IFDEF LOAD_FROM_RESOURCE}
{$IF Declared( Classes )}
type
  TMemoryStream_ = class( Classes.TMemoryStream );
{$IFEND Declared( Classes )}

function ExtractPointer( Source : Pointer; Len : Cardinal; var Decompressed : Pointer; Password : string = ''; ArchiveID : Byte = 0 ) : Int64;
  function ExtractZLIB( Source : Pointer; Len : Cardinal; var Decompressed : Pointer; ZLibHeader: Boolean = True ) : Int64;
  {$IF NOT Declared( MAX_WBITS )}
  const
    MAX_WBITS = 15; // 32K LZ77 window
  {$IFEND MAX_WBITS}
  var
    strm : TZStreamRec;
    {$IF Declared( inflateInit2_ )}
    Bits : integer;
    {$IFEND inflateInit2_}
    L    : {$IF Declared( zlibCompileFlags )}Cardinal{$ELSE}Integer{$IFEND}; // Native D7 uses Integer while JCL uses Cardinal 
  begin
    result := -10;
    if NOT Assigned( Source ) OR ( Len = 0 ) then
      Exit;
    if Assigned( Decompressed ) then
      ReallocMem( Decompressed, 0 );
    // Initialize ZLib StreamRecord
    FillChar( strm, SizeOf( strm ), 0 );
    strm.next_in   := Source;
    strm.avail_in  := Len;

    {$IF Declared( inflateInit2_ )}
    if ZLibHeader then
      Bits := MAX_WBITS
    else
      Bits := -MAX_WBITS; // no zLib header => .zip compatible

    Result := inflateInit2_( strm, Bits, ZLIB_VERSION, sizeof(TZStreamRec) );
    {$ELSE}
    Result := inflateInit_( strm, ZLIB_VERSION, sizeof(TZStreamRec) );
    {$IFEND inflateInit2_}
    if Result < 0 then
      Exit;

    L := Len*4;
    GetMem( Decompressed, L );

    strm.next_out := Decompressed;
    strm.avail_out := L;
    while ( strm.avail_in > 0 ) do
      begin
      if ( strm.avail_out = 0 ) then
        begin
        strm.avail_out := strm.avail_in*4;
        try
          ReallocMem( Decompressed, L+strm.avail_out );
        except
          ReallocMem( Decompressed, 0 );
          inflateEnd( strm );
          result := 0;
          Exit;
        end;
        strm.next_out := Decompressed;
        Inc( strm.next_out, L );
        L := L+strm.avail_out;
        end;

      Result := inflate( strm, Z_NO_FLUSH );
      case Result of
        Z_STREAM_END             : break;
        Z_VERSION_ERROR..Z_ERRNO : begin
                                   ReallocMem( Decompressed, 0 );
                                   inflateEnd( strm );
                                   result := 0;
                                   Exit;
                                   end;
      end;
      end;

    Result := strm.total_out;
    if ( L <> Result ) then
      ReallocMem( Decompressed, Result );
    inflateEnd( strm );
  end;

  {$IF Declared( inflateInit2_ )}
  function ExtractGZIP( Source : PByte; Len : Cardinal; var Decompressed : Pointer{$IF Declared( CRC32 )}; CheckHeaderCRC : boolean = True{$IFEND} ) : Int64;
    function ReadBuffer( var Source : PByte; var Len : Cardinal; const Dest : PByte; count : Cardinal{$IF Declared( CRC32 )}; var HeaderCRC : Cardinal; ComputeHeaderCRC : boolean = True{$IFEND} ) : boolean; {$IF CompilerVersion >= 23}inline;{$IFEND}
    begin
      result := False;
      if ( Count > Len ) then
        Exit;
      Move( Source^, dest^, count );
      Inc( Source, count );
      Dec( Len, count );

      {$IF Declared( CRC32 )}
      if ComputeHeaderCRC then
        HeaderCRC := crc32( HeaderCRC, {$IFDEF JCL}PBytef{$ELSE}PByte{$ENDIF}( Dest ), count );
      {$IFEND CRC32}

      result := True;
    end;
    function ReadCString( var Source : PByte; var Len : Cardinal{$IF Declared( CRC32 )}; var HeaderCRC : Cardinal; ComputeHeaderCRC : boolean = True{$IFEND} ): AnsiString; {$IF CompilerVersion >= 23}inline;{$IFEND}
    var
      Buf : AnsiChar;
    begin
      Result := '';
      Buf    := #0;
      repeat
        if NOT ReadBuffer( Source, Len, @Buf, SizeOf( Buf ){$IF Declared( CRC32 )}, HeaderCRC, ComputeHeaderCRC{$IFEND} ) then
          Break;
        if Buf = #0 then
          Break;
        Result := Result + Buf;
      until False;
    end;
  type
    TJclGZIPHeader = packed record
      ID1: Byte;
      ID2: Byte;
      CompressionMethod: Byte;
      Flags: Byte;
      ModifiedTime: Cardinal;
      ExtraFlags: Byte;
      OS: Byte;
    end;
  const
    // ID1 and ID2 fields
    JCL_GZIP_ID1 = $1F; // value for the ID1 field
    JCL_GZIP_ID2 = $8B; // value for the ID2 field
    // Compression Model field
    JCL_GZIP_CM_DEFLATE = 8; // Zlib classic

    // Flags field : extra fields for the header
    JCL_GZIP_FLAG_CRC     = $02; // a CRC16 for the header is present  
    JCL_GZIP_FLAG_EXTRA   = $04; // extra fields present
    JCL_GZIP_FLAG_NAME    = $08; // original file name is present
    JCL_GZIP_FLAG_COMMENT = $10; // comment is present
  var
    Header           : TJclGZIPHeader;
    ExtraFieldLength : Word;
    ExtraField       : string;
    OriginalFileName : {$IF Declared( TFileName )}TFileName{$ELSE}String{$IFEND};
    Comment          : String;
  {$IF Declared( CRC32 )}
    HeaderCRC        : Cardinal;
  {$IFEND CRC32}
    StoredHeaderCRC16: Word;
  begin
    result := -17;
  {$IF Declared( CRC32 )}
    HeaderCRC := 0; // crc32(0, nil, 0);
  {$IFEND CRC32}
    if NOT ReadBuffer( Source, Len, @Header, SizeOf( Header ){$IF Declared( CRC32 )}, HeaderCRC, CheckHeaderCRC{$IFEND} ) then
      Exit;

    if ( Header.ID1 <> JCL_GZIP_ID1 ) or ( Header.ID2 <> JCL_GZIP_ID2 ) then
      begin
      result := -16;
      Exit;
  //    raise EJclCompressionError.CreateResFmt( @RsCompressionGZipInvalidID, [ Header.ID1, Header.ID2 ] );
      end;

    if ( Header.CompressionMethod <> JCL_GZIP_CM_DEFLATE ) then
      begin
      result := -15;
      Exit;
  //    raise EJclCompressionError.CreateResFmt( @RsCompressionGZipUnsupportedCM, [ Header.CompressionMethod ] );
      end;

    if ( ( Header.Flags and JCL_GZIP_FLAG_EXTRA ) <> 0 ) then
      begin
      ExtraFieldLength := 0;
      if NOT ReadBuffer( Source, Len, @ExtraFieldLength, SizeOf( ExtraFieldLength ){$IF Declared( CRC32 )}, HeaderCRC, CheckHeaderCRC{$IFEND} ) then
        begin
        result := -14;
        Exit;
        end;

      SetLength( ExtraField, ExtraFieldLength );
      if NOT ReadBuffer( Source, Len, @ExtraField[1], ExtraFieldLength{$IF Declared( CRC32 )}, HeaderCRC, CheckHeaderCRC{$IFEND} ) then
        begin
        result := -13;
        Exit;
        end;
      end;

    if ( ( Header.Flags and JCL_GZIP_FLAG_NAME ) <> 0 ) then
      OriginalFileName := {$IF Declared( TFileName )}TFileName{$ELSE}String{$IFEND}( ReadCString( Source, Len{$IF Declared( CRC32 )}, HeaderCRC, CheckHeaderCRC{$IFEND} ) );
    if ( ( Header.Flags and JCL_GZIP_FLAG_COMMENT ) <> 0 ) then
      Comment := string( ReadCString( Source, Len{$IF Declared( CRC32 )}, HeaderCRC, CheckHeaderCRC{$IFEND} ) );

  //{$IF Declared( CRC32 )}
  //  if CheckHeaderCRC then
  //    ComputedHeaderCRC16 := HeaderCRC and $FFFF;
  //{$IFEND CRC32}

    if ( ( Header.Flags and JCL_GZIP_FLAG_CRC ) <> 0 ) then
      begin
      if NOT ReadBuffer( Source, Len, @StoredHeaderCRC16, SizeOf( StoredHeaderCRC16 ){$IF Declared( CRC32 )}, HeaderCRC, False{$IFEND} ) then
        begin
        result := -12;
        Exit;
        end;
      {$IF Declared( CRC32 )}
      if CheckHeaderCRC and ( {ComputedHeaderCRC16}( HeaderCRC and $FFFF ) <> StoredHeaderCRC16 ) then
        begin
        result := -11;
        Exit;
  //      raise EJclCompressionError.CreateRes( @RsCompressionGZipHeaderCRC );
        end;
      {$IFEND CRC32}
      end;

    result := ExtractZLIB( Source, Len, Decompressed, {ZLibHeader}False );
  end;
  {$IFEND inflateInit2_}

  {$IF Declared( Classes )}
  function ExtractStreamGZIP( var ASourceStream : TStream ) : Integer;
  var
    Archive : TJclDecompressStream;
    Header  : Array [ 0..3 ] of AnsiChar;
    Dst     : TStream;
  begin
    result := -5;
    if NOT Assigned( ASourceStream ) then
      Exit;
    Dst := TMemoryStream.Create;

    if ( ASourceStream.Position = ASourceStream.Size ) then
      ASourceStream.Position := 0;    

    result := -4;
    if ( ASourceStream.Size-ASourceStream.Position <= Length( Header ) ) then
      Exit;
    ASourceStream.Read( Header[ Low( Header ) ], Length( Header ) );
  //  ASourceStream.Position := ASourceStream.Position-Length( Header );
    result := -3;
    if ( Header <> 'GZIP' ) then
      Exit;

    Archive := TJclGZIPDecompressionStream.Create( ASourceStream );
    Archive.SaveToStream( Dst );

    Archive.Free;
    ASourceStream.free;
    ASourceStream := dst;
    ASourceStream.Position := 0;

    result := 0;
  end;

  function ExtractStream7z( var ASourceStream : TStream; Password : string = ''; ArchiveID : Byte = 0 ) : Integer;
  var
    Archive : TJclDecompressArchive;
    Header  : Array [0..1] of AnsiChar;
    Dst     : TStream;
  begin
    {$IF Declared( DLL7z_IsInitDLL )}
    result := -6;
    if NOT DLL7z_IsInitDLL then
      Exit;
    {$IFEND}

    result := -5;
    if NOT Assigned( ASourceStream ) then
      Exit;
    Dst := TMemoryStream.Create;

    if ( ASourceStream.Position = ASourceStream.Size ) then
      ASourceStream.Position := 0;

    result := -4;
    if ( ASourceStream.Size-ASourceStream.Position <= Length( Header ) ) then
      Exit;
    ASourceStream.Read( Header[ Low( Header ) ], Length( Header ) );
    ASourceStream.Position := ASourceStream.Position-Length( Header );

    result := -3;
    if ( Header <> '7z' ) AND ( Header <> '7Z' ) then
      Exit;

    Archive := TJcl7zDecompressArchive.Create( ASourceStream, 0, False );
    Archive.Password := Password;
    try
      Archive.ListFiles;
    except
      Archive.Free;
      result := -2;
      Exit;
    end;

    if ( ArchiveID < Archive.ItemCount ) then
      begin
      Archive.Items[ ArchiveID ].Stream     := Dst;
      Archive.Items[ ArchiveID ].OwnsStream := false;
      Archive.Items[ ArchiveID ].Selected   := True;
      Archive.ExtractSelected;
      Dst.Position := 0;

      ASourceStream.free;
      ASourceStream := dst;

      result := 0;
      end
    else
      result := -1;
    Archive.Free;
  end;
  {$IFEND}
const
  PREFIX_ : Array [ 0..3{$IFDEF LZMA}+2{$ENDIF} ] of AnsiString = ( 'mz', '7z', 'zlib', 'gzip'{$IFDEF LZMA}, 'lzma', 'lzm2'{$ENDIF} );
{$IF Declared( Classes )}
var
  S : TStream;
{$IFEND}
begin
  result := -5;
  if NOT Assigned( Source ) then
    Exit;

  result := -4;
  if ( Len < 4 ) then
    Exit;
  result := -3;
  if ( CompareStringA( LOCALE_USER_DEFAULT, NORM_IGNORECASE, Source, Length( PREFIX_[ 0 ] ), PAnsiChar( PREFIX_[ 0 ] ), Length( PREFIX_[ 0 ] ) ) = 2 ) then // Uncompressed
    begin
//    ReallocMem( Decompressed, Len );
//    Move( Source^, Decompressed^, Len );
    Decompressed := Source;
    result := Len;
    Exit;
    end
  else if ( CompareStringA( LOCALE_USER_DEFAULT, NORM_IGNORECASE, Source, Length( PREFIX_[ 1 ] ), PAnsiChar( PREFIX_[ 1 ] ), Length( PREFIX_[ 1 ] ) ) = 2 ) then // 7z
    begin
    {$IF Declared( Classes )}
    S := TMemoryStream.Create;
    TMemoryStream_( S ).SetPointer( Source, Len );
//    S.Write( Source^, Len );
    result := ExtractStream7z( S, Password, ArchiveID );
    if ( result = 0 ) then
      begin
      ReallocMem( Decompressed, S.Size );
      Move( TMemoryStream( S ).Memory^, Decompressed^, S.Size );
      result := S.Size;
      end;
    S.free;
    {$ELSE}
    result := -6;
    {$IFEND}
    end
  else if ( CompareStringA( LOCALE_USER_DEFAULT, NORM_IGNORECASE, Source, Length( PREFIX_[ 2 ] ), PAnsiChar( PREFIX_[ 2 ] ), Length( PREFIX_[ 2 ] ) ) = 2 ) then // ZLib
    result := ExtractZLIB( {$IF CompilerVersion < 23}PByte( PAnsiChar( Source )+Length( PREFIX_[ 2 ] ) ){$ELSE}PByte( Source )+Length( PREFIX_[ 2 ] ){$IFEND}, Len-Length( PREFIX_[ 2 ] ), Decompressed )
  {$IFDEF lzma}
  else if ( CompareStringA( LOCALE_USER_DEFAULT, NORM_IGNORECASE, Source, Length( PREFIX_[ 4 ] ), PAnsiChar( PREFIX_[ 4 ] ), Length( PREFIX_[ 4 ] ) ) = 2 ) then // LZMA
    result := ExtractLZMA( {$IF CompilerVersion < 23}PByte( PAnsiChar( Source )+Length( PREFIX_[ 4 ] ) ){$ELSE}PByte( Source )+Length( PREFIX_[ 4 ] ){$IFEND}, Len-Length( PREFIX_[ 4 ] ), Decompressed )
  else if ( CompareStringA( LOCALE_USER_DEFAULT, NORM_IGNORECASE, Source, Length( PREFIX_[ 5 ] ), PAnsiChar( PREFIX_[ 5 ] ), Length( PREFIX_[ 5 ] ) ) = 2 ) then // LZMA2
    result := ExtractLZMA2( {$IF CompilerVersion < 23}PByte( PAnsiChar( Source )+Length( PREFIX_[ 5 ] ) ){$ELSE}PByte( Source )+Length( PREFIX_[ 5 ] ){$IFEND}, Len-Length( PREFIX_[ 5 ] ), Decompressed )
  {$ENDIF lzma}
  else if ( CompareStringA( LOCALE_USER_DEFAULT, NORM_IGNORECASE, Source, Length( PREFIX_[ 3 ] ), PAnsiChar( PREFIX_[ 3 ] ), Length( PREFIX_[ 3 ] ) ) = 2 ) then // Gzip
    {$IF Declared( ExtractGZIP )}
    result := ExtractGZIP( {$IF CompilerVersion < 23}PByte( PAnsiChar( Source )+Length( PREFIX_[ 3 ] ) ){$ELSE}PByte( Source )+Length( PREFIX_[ 3 ] ){$IFEND}, Len-Length( PREFIX_[ 3 ] ), Decompressed );
    {$ELSEIF Declared( Classes )}
    begin
    S := TMemoryStream.Create;
    TMemoryStream_( S ).SetPointer( PByte( {$IF CompilerVersion < 23}PAnsiChar( Source )+Length( PREFIX_[ 3 ] ){$ELSE}PByte( Source )+Length( PREFIX_[ 3 ] ){$IFEND} ), Len-Length( PREFIX_[ 3 ] ) );
//    S.Write( PByte( {$IF CompilerVersion < 23}PAnsiChar( Source )+Length( PREFIX_[ 3 ] ){$ELSE}PByte( Source )+Length( PREFIX_[ 3 ] ){$IFEND} )^, Len-Length( PREFIX_[ 2 ] ) );
    result := ExtractStreamGZIP( S );
    if ( result = 0 ) then
      begin
      ReallocMem( Decompressed, S.Size );
      Move( TMemoryStream( S ).Memory^, Decompressed^, S.Size );
      result := S.Size;
      end;
    S.free;
    end;
    {$ELSE}
    result := -6;
    {$IFEND}
end;

function MemoryResourceExists( var ResourceName : string ) : HRSRC;
  {$IF NOT Declared( ChangeFileExt )}
  function ChangeFileExt( FileName : string; Extension : String = '' ) : String;
    function PosEx(const SubStr, S: string; Offset: Cardinal = 1): Integer;
    var
      I,X: Integer;
      Len, LenSubStr: Integer;
    begin
      if Offset = 1 then
        Result := Pos(SubStr, S)
      else
      begin
        I := Offset;
        LenSubStr := Length(SubStr);
        Len := Length(S) - LenSubStr + 1;
        while I <= Len do
        begin
          if S[I] = SubStr[1] then
          begin
            X := 1;
            while (X < LenSubStr) and (S[I + X] = SubStr[X + 1]) do
              Inc(X);
            if (X = LenSubStr) then
            begin
              Result := I;
              exit;
            end;
          end;
          Inc(I);
        end;
        Result := 0;
      end;
    end;
  const
    TD = '\';
    P  = '.';
  var
    i, j : Integer;
  begin
    i := Pos( TD, FileName );
    if ( i > 0 ) then
      begin
      j := i;
      while ( j > 0 ) do
        begin
        j := PosEx( TD, FileName, j+1 );
        if ( j > 0 ) then
          i := j;
        end;
      end;

    j := PosEx( P, FileName, i+1 );
    if ( j > 0 ) then
      begin
      i := j;
      while ( j > 0 ) do
        begin
        j := PosEx( TD, FileName, j+1 );
        if ( j > 0 ) then
          i := j;
        end;
      end;
    if ( i = 0 ) then
      result := FileName + Extension
    else
      result := Copy( FileName, 1, i-1 ) + Extension;
  end;
  {$IFEND}
const
  NamePrefix = 'DLL'; // Resource DLLs need to start with a Letter
  RES_TYPE_  = 'DLL'; // RT_RCDATA{10};  
begin
  result := 0;
  if ( ResourceName = '' ) then
    Exit;
  ResourceName := ChangeFileExt( ResourceName, '' );
  {$IF Declared( CharInSet )}
  if not CharInSet( ResourceName[ {$IF CompilerVersion >= 24}Low( ResourceName ){$ELSE}1{$IFEND} ], ['a'..'z','A'..'Z'] ) then
  {$ELSE}
  if ( ResourceName[ {$IF CompilerVersion >= 24}Low( ResourceName ){$ELSE}1{$IFEND} ] < 'a' ) and
     ( ResourceName[ {$IF CompilerVersion >= 24}Low( ResourceName ){$ELSE}1{$IFEND} ] > 'z' ) and
     ( ResourceName[ {$IF CompilerVersion >= 24}Low( ResourceName ){$ELSE}1{$IFEND} ] < 'A' ) and
     ( ResourceName[ {$IF CompilerVersion >= 24}Low( ResourceName ){$ELSE}1{$IFEND} ] > 'Z' ) then
  {$IFEND}
    ResourceName := NamePrefix + ResourceName;

  result := FindResource( hInstance, PChar( ResourceName ), RES_TYPE_ );
end;

function MemoryLoadLibrary( ResourceName : string; var Module : PMemoryModule; {$IFDEF USE_STREAMS}Password : string = '';{$ENDIF} Flags : Cardinal = 0 ): ShortInt; stdcall;
const
  RES_TYPE_ = 'DLL'; // RT_RCDATA{10};
var
  HRes   : HRSRC;
  HG     : HGlobal;
  Data   : Pointer;
  Extract: Pointer;
  res    : Int64;
begin
  result := -32;
  Module := nil;

  HRes := MemoryResourceExists( ResourceName );
  if ( HRes = 0 ) then
    begin
    SetLastError( ERROR_RESOURCE_NAME_NOT_FOUND{1814} );
    Exit;
    end;

  {$IFDEF MEMORY_REFCOUNT}
  if Assigned( ModuleManager ) AND
     ( ( LOAD_LIBRARY_AS_DATAFILE           AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE ) AND
     ( ( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE ) AND
     ( ( DONT_RESOLVE_DLL_REFERENCES        AND Flags ) <> DONT_RESOLVE_DLL_REFERENCES ) AND
     ( ( LOAD_LIBRARY_AS_IMAGE_RESOURCE     AND Flags ) <> LOAD_LIBRARY_AS_IMAGE_RESOURCE ) then
    begin
    Module := ModuleManager.GetHandle( ResourceName, True{IsResource} );
    if Assigned( Module ) then
      begin
      Inc( Module.refCount );
      result := 0;
      Exit;
      end;
    end;
  {$ENDIF MEMORY_REFCOUNT}

  HG := LoadResource( hInstance, HRes );
  if ( HG = 0 ) then
    begin
    SetLastError( ERROR_INVALID_DATA{13} );
    Exit;
    end;
  Data := LockResource( HG );

  Extract := nil;
  res := ExtractPointer( Data, SizeOfResource( hInstance, HRes ), Extract{$IFDEF USE_STREAMS}, Password{$ENDIF} );
  if ( res > 0 ) then
    begin
    result := MemoryLoadLibrary( Extract, {SizeOfResource( hInstance, HRes ),} Module, Flags );
    {$IFDEF GetModuleHandle}
    if ( ( LOAD_LIBRARY_AS_DATAFILE           AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE ) AND
       ( ( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE ) AND
       ( ( DONT_RESOLVE_DLL_REFERENCES    AND Flags ) <> DONT_RESOLVE_DLL_REFERENCES ) AND
       ( ( LOAD_LIBRARY_AS_IMAGE_RESOURCE AND Flags ) <> LOAD_LIBRARY_AS_IMAGE_RESOURCE ) AND ( result = 0 ) then
      begin
      ModuleManager.Add( Module, Data, ResourceName, True{IsResource} );
      {$IFDEF MEMORY_REFCOUNT}
      Module.refCount := 1;
      {$ENDIF MEMORY_REFCOUNT}
      end;
    {$ENDIF GetModuleHandle}
    {$IFDEF REGISTER_IN_PEB}
    if ( result = 0 ) then
      UpdatePEBName( Module, ResourceName ); // real name for stack walkers
    {$ENDIF REGISTER_IN_PEB}
    end
  else if ( res = 0 ) then
    result := -32
  else
    result := res;

  if ( res <= 0 ) then
    SetLastError( ERROR_INVALID_DATA{13} );
  UnlockResource( HG );
  FreeResource( HG );
  if ( Extract <> Data ) then
    ReallocMem( Extract, 0 );
end;
{$ENDIF}

function MemoryLoadLibrary( data: Pointer; var Module : PMemoryModule; Flags : Cardinal = 0 ): ShortInt; stdcall;
var
  Code : Pointer;
  {$IFDEF MEMORY_REFCOUNT}
  IsNormalLoad : Boolean;
  Existing     : PMemoryModule;
  {$ENDIF MEMORY_REFCOUNT}
begin
  Code   := nil;
  Module := nil;

  {$IFDEF MEMORY_REFCOUNT}
  IsNormalLoad := ( ( LOAD_LIBRARY_AS_DATAFILE           AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE ) AND
                  ( ( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE ) AND
                  ( ( DONT_RESOLVE_DLL_REFERENCES        AND Flags ) <> DONT_RESOLVE_DLL_REFERENCES ) AND
                  ( ( LOAD_LIBRARY_AS_IMAGE_RESOURCE     AND Flags ) <> LOAD_LIBRARY_AS_IMAGE_RESOURCE );
  if IsNormalLoad AND Assigned( ModuleManager ) then
    begin
    Existing := ModuleManager.GetHandle( data );
    if Assigned( Existing ) then
      begin
      Inc( Existing.refCount );
      Module := Existing;
      result := 0;
      Exit;
      end;
    end;
  {$ENDIF MEMORY_REFCOUNT}

  result := MemoryLoadLibrary_1( data, Code, Module, Flags );
  if ( result < 0 ) then
    Exit;

  if ( ( LOAD_LIBRARY_AS_DATAFILE           AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE ) AND
     ( ( LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE AND Flags ) <> LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE ) AND
     ( ( DONT_RESOLVE_DLL_REFERENCES        AND Flags ) <> DONT_RESOLVE_DLL_REFERENCES ) AND
     ( ( LOAD_LIBRARY_AS_IMAGE_RESOURCE     AND Flags ) <> LOAD_LIBRARY_AS_IMAGE_RESOURCE ) then
    begin
    result := MemoryLoadLibrary_2( Module );
    if ( result <> 0 ) then
      Exit;

    result := MemoryLoadLibrary_3( Module, Code );

    {$IFDEF GetModuleHandle}
    if ( result = 0 ) then
      begin
      if NOT Assigned( ModuleManager ) then
        ModuleManager := tModuleManager.Create;
      ModuleManager.Add( Module, Data, ''{$IFDEF LOAD_FROM_RESOURCE}, False{IsResource}{$ENDIF} );
      {$IFDEF MEMORY_REFCOUNT}
      Module.refCount := 1;
      {$ENDIF MEMORY_REFCOUNT}
      end;
    {$ENDIF GetModuleHandle}
    end;
end;

function MemoryGetProcAddress( module: PMemoryModule; const name: PAnsiChar ): Pointer; stdcall;
var
  codebase: Pointer;
  idx: Integer;
  i: Cardinal;
  nameRef: PDWORD;
  ordinal: PWord;
  exportDir: PIMAGE_EXPORT_DIRECTORY;
  directory: PIMAGE_DATA_DIRECTORY;
  temp: PDWORD;
begin
  Result := nil;
  if NOT Assigned( module ) then
    Exit;
  if ( Name = '' ) then
    Exit;

  codebase := module.codeBase;
  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_EXPORT );
  // no export table found
  if directory.Size = 0 then
    begin
    SetLastError( ERROR_PROC_NOT_FOUND );
    Exit;
    end;

  exportDir := PIMAGE_EXPORT_DIRECTORY( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + directory.VirtualAddress );
  // DLL doesn't export anything
  if ( exportDir.NumberOfNames = 0 ) or ( exportDir.NumberOfFunctions = 0 ) then
    begin
    SetLastError( ERROR_PROC_NOT_FOUND );
    Exit;
    end;

  // search function name in list of exported names
  nameRef := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + {$IF Defined( FPC ) OR ( CompilerVersion < 21 )}Cardinal{$IFEND}( exportDir.AddressOfNames ) );
  ordinal := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + {$IF Defined( FPC ) OR ( CompilerVersion < 21 )}Cardinal{$IFEND}( exportDir.AddressOfNameOrdinals ) );
  idx := -1;
  for i := 0 to exportDir.NumberOfNames - 1 do
    begin
    if StrComp( name, PAnsiChar( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + nameRef^ ) ) = 0 then
      begin
      idx := ordinal^;
      Break;
      end;
    Inc( nameRef );
    Inc( ordinal );
    end;

  // exported symbol not found
  if ( idx = -1 ) then
    begin
    SetLastError( ERROR_PROC_NOT_FOUND );
    Exit;
    end;

  // name <-> ordinal number don't match
  if ( Cardinal( idx ) > exportDir.NumberOfFunctions ) then
    begin
    SetLastError( ERROR_PROC_NOT_FOUND );
    Exit;
    end;

  // AddressOfFunctions contains the RVAs to the "real" functions 
  temp := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + {$IF Defined( FPC ) OR ( CompilerVersion < 21 )}Cardinal{$IFEND}( exportDir.AddressOfFunctions ) + {$IF Defined( FPC ) OR ( CompilerVersion < 21 )}Cardinal{$IFEND}( idx )*4 );
  Result := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + temp^ );
end;

{$IFDEF MEMORY_DEPENDENCIES}
// Resolve an exported function of a memory module by ordinal (name-based lookup lives in
// MemoryGetProcAddress). Forwarded exports are not followed - same limitation as the name path.
function MemoryGetProcAddressByOrdinal( module : PMemoryModule; ordinal : Word ) : Pointer;
var
  codebase  : Pointer;
  exportDir : PIMAGE_EXPORT_DIRECTORY;
  directory : PIMAGE_DATA_DIRECTORY;
  funcRVA   : PDWORD;
  idx       : Integer;
begin
  Result := nil;
  if NOT Assigned( module ) then
    Exit;
  codebase  := module.codeBase;
  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_EXPORT );
  if ( directory.Size = 0 ) then
    Exit;
  exportDir := PIMAGE_EXPORT_DIRECTORY( Pointer( NativeUInt( codebase ) + directory.VirtualAddress ) );
  if ( exportDir.NumberOfFunctions = 0 ) then
    Exit;
  idx := Integer( ordinal ) - Integer( exportDir.Base );
  if ( idx < 0 ) OR ( Cardinal( idx ) >= exportDir.NumberOfFunctions ) then
    Exit;
  funcRVA := PDWORD( Pointer( NativeUInt( codebase ) + exportDir.AddressOfFunctions + Cardinal( idx ) * 4 ) );
  if ( funcRVA^ = 0 ) then
    Exit;
  Result := Pointer( NativeUInt( codebase ) + funcRVA^ );
end;

// Called from BuildImportTable for every imported module name. Returns a memory module to satisfy
// the import from, or nil to let the caller fall back to the on-disk loader.
function ResolveMemoryDependency( const AName : string ) : PMemoryModule;
var
  resName : string;
  data    : Pointer;
  size    : NativeUInt;
  dep     : PMemoryModule;
  rc      : ShortInt;
  hasSrc  : Boolean;
  {$IFDEF LOAD_FROM_RESOURCE}
  tryRes  : string;
  {$ENDIF}
begin
  Result := nil;
  if NOT Assigned( ModuleManager ) then
    Exit;

  // 1. Already loaded as a memory module -> reuse it.
  //    a) loaded earlier as a dependency (works even if resource name <> module name)
  Result := ModuleManager.GetDataHandle( AName );
  if Assigned( Result ) then
    begin
    {$IFDEF MEMORY_REFCOUNT}
    Inc( Result.refCount ); // another importer now shares this dependency too
    {$ENDIF MEMORY_REFCOUNT}
    Exit;
    end;
  //    b) loaded by the application under this very name
  Result := ModuleManager.GetHandleByName( AName );
  if Assigned( Result ) then
    begin
    {$IFDEF MEMORY_REFCOUNT}
    Inc( Result.refCount );
    {$ENDIF MEMORY_REFCOUNT}
    Exit;
    end;

  // 2. Explicit registration has precedence.
  hasSrc := ModuleManager.FindData( AName, resName, data, size );

  // 3. Convention fallback: an RT-'DLL' resource named like the import.
  {$IFDEF LOAD_FROM_RESOURCE}
  if ( NOT hasSrc ) then
    begin
    tryRes := AName;
    if ( MemoryResourceExists( tryRes ) <> 0 ) then
      begin
      hasSrc  := True;
      resName := AName; // let the resource overload normalize the name
      data    := nil;
      size    := 0;
      end;
    end;
  {$ENDIF LOAD_FROM_RESOURCE}

  if ( NOT hasSrc ) then
    Exit; // not one of ours -> on-disk fallback

  // 4. Circular-dependency guard (memory-only cycles fail gracefully rather than recurse).
  if ( NOT ModuleManager.BeginLoad( AName ) ) then
    begin
    SetLastError( 1059 {ERROR_CIRCULAR_DEPENDENCY} );
    Exit;
    end;

  try
    dep := nil;
    rc  := -32;
    if ( resName <> '' ) then
      begin
      {$IFDEF LOAD_FROM_RESOURCE}
      rc := MemoryLoadLibrary( resName, dep );
      {$ENDIF LOAD_FROM_RESOURCE}
      end
    else if Assigned( data ) then
      rc := MemoryLoadLibrary( data, dep );
    if ( rc = 0 ) AND Assigned( dep ) then
      begin
      Result := dep;
      ModuleManager.SetDataHandle( AName, dep ); // remember it under the MODULE name
      end;
  finally
    ModuleManager.EndLoad( AName );
  end;
end;

procedure MemoryRegisterDllData( const ModuleName : string; Data : Pointer; Size : NativeUInt );
begin
  if NOT Assigned( ModuleManager ) then
    ModuleManager := tModuleManager.Create;
  ModuleManager.RegisterData( ModuleName, Data, Size );
end;

procedure MemoryRegisterDllData( const ModuleName, ResourceName : string );
begin
  if NOT Assigned( ModuleManager ) then
    ModuleManager := tModuleManager.Create;
  ModuleManager.RegisterData( ModuleName, ResourceName );
end;

procedure MemoryUnregisterDllData( const ModuleName : string );
begin
  if Assigned( ModuleManager ) then
    ModuleManager.UnregisterData( ModuleName );
end;
{$ENDIF MEMORY_DEPENDENCIES}

procedure MemoryFreeLibrary( var module: PMemoryModule ); stdcall;
var
  i: Integer;
  DllEntry: TDllEntryProc;
begin
  if module = nil then
    Exit;

  {$IFDEF MEMORY_REFCOUNT}
  Dec( module.refCount );
  if ( module.refCount > 0 ) then
    begin
    module := nil; // other callers still hold this module - just drop our own reference to it
    Exit;
    end;
  {$ENDIF MEMORY_REFCOUNT}

  if module.initialized then
    begin
    // notify library about detaching from process
    if module.headers.X64 then
      @DllEntry := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( module.codeBase ) + module.headers.headers64.OptionalHeader.AddressOfEntryPoint )
    else
      @DllEntry := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( module.codeBase ) + module.headers.headers32.OptionalHeader.AddressOfEntryPoint );
    DllEntry( HINST( module.codeBase ), DLL_PROCESS_DETACH, nil );
    end;

  // Drop the unwind table only after DLL_PROCESS_DETACH ran (it may still raise/unwind),
  // but before the image memory is released.
  UnregisterExceptionTable( module );
  {$IF Defined( MEMORY_SEH_X86 ) AND NOT Defined( CPUX64 )}
  UnregisterInvertedFunctionTableEntry( module );
  {$IFEND}
  {$IF Defined( MEMORY_FROM_ADDRESS_X64 ) AND Defined( CPUX64 )}
  UnregisterInvertedFunctionTableEntryX64( module );
  {$IFEND}
  {$IFDEF REGISTER_IN_PEB}
  {$IFDEF MEMORY_HANDLE_TLS}
  if module.tlsHandled then
    MM_ReleaseTlsEntry( module ); // must run before the fake LDR entry is freed
  {$ENDIF MEMORY_HANDLE_TLS}
  UnregisterFromPEB( module ); // must happen before the image memory goes away
  {$ENDIF REGISTER_IN_PEB}

  if Length( module.modules ) <> 0 then
    begin
    // free previously opened libraries
    for i := Low( module.Modules ) to High( module.Modules ) do
      begin
      if ( module.modules[ i ].Handle <> 0 ) {$IFDEF GetModuleHandle_BuildImportTable}and module.modules[ i ].Free{$ENDIF} then
        FreeLibrary_Internal( module.modules[ i ].Handle );
      end;
    {$IF Defined( FastMM4 ) OR Defined( FastMM5 )}
    UnregisterLeakBlock( DynArrayBlockBase( Pointer( module.modules ) ) );
    {$IFEND}
    SetLength( module.modules, 0 );
    end;

  if ( module.codeBase <> nil ) then // release memory of library
    VirtualFree( module.codeBase, 0, MEM_RELEASE );

  HeapFree( GetProcessHeap, 0, module );
  {$IFDEF GetModuleHandle}
  {$IFDEF MEMORY_DEPENDENCIES}
  ModuleManager.ClearDataHandle( Module ); // drop the dependency cache entry, if any
  {$ENDIF MEMORY_DEPENDENCIES}
  ModuleManager.Del( Module );
  {$ENDIF GetModuleHandle}
  Module := nil;  
end;

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
function CheckSumMappedFile( Module : PMemoryModule; HeaderSum : PCardinal; CheckSum : PCardinal ) : PIMAGE_NT_HEADERS32;
  function ChkSum( PartialSum : Cardinal; Source : PWord; Length : Cardinal ) : Word;
  begin
    // Compute the word wise checksum allowing carries to occur into the
    // high order half of the checksum longword.
    while ( Length > 0 ) do
      begin
      PartialSum := PartialSum + Source^; // *Source++;
      PartialSum := ( PartialSum SHR 16 ) + ( PartialSum AND $ffff );
      Inc( Source );
      Dec( Length );
      end;
    // Fold final carry into a single word result and return the resultant value.
    result := ( ( ( PartialSum SHR 16 ) + PartialSum ) AND $ffff );
  end;
var
  AdjustSum1 : PWord;
  AdjustSum2 : PWord;
  PartialSum : Word;
  Size       : Cardinal;
begin
  result := nil;
  if ( Module = nil ) then
    Exit;
  if ( HeaderSum = nil ) AND ( CheckSum = nil ) then
    Exit;
  if ( HeaderSum <> nil ) then
    HeaderSum^ := 0;
  if ( CheckSum <> nil ) then
    CheckSum^ := 0;

  result := PIMAGE_NT_HEADERS32( NativeInt( Module^.codeBase ) + PImageDosHeader( Module^.codeBase )._lfanew );
  if ( result.Signature <> IMAGE_NT_SIGNATURE ) then
    begin
    result := nil;
    Exit;
    end;

  // If the file is an image file, then subtract the two checksum words
  // in the optional header from the computed checksum before adding
  // the file length, and set the value of the header checksum.
  if Module^.headers.X64 then
    begin
    Size := Module^.headers.headers64.OptionalHeader.SizeOfImage;
    if ( HeaderSum <> nil ) then
      HeaderSum^ := Module^.headers.headers64.OptionalHeader.CheckSum;
    AdjustSum1 := PWord( @Module^.headers.headers64.OptionalHeader.CheckSum );
    AdjustSum2 := AdjustSum1;
    Inc( AdjustSum2 );
    end
  else
    begin
    Size := Module^.headers.headers32.OptionalHeader.SizeOfImage;
    if ( HeaderSum <> nil ) then
      HeaderSum^ := Module^.headers.headers32.OptionalHeader.CheckSum;
    AdjustSum1 := PWord( @Module^.headers.headers32.OptionalHeader.CheckSum );
    AdjustSum2 := AdjustSum1;
    Inc( AdjustSum2 );
    end;

  // Compute the checksum of the file and zero the header checksum value.
  PartialSum := ChkSum( 0, PWord( Module.codeBase ), ( Size + 1 ) SHR 1 );

  {$R-}
  PartialSum := PartialSum - Byte( PartialSum < AdjustSum1^ );
  PartialSum := PartialSum - AdjustSum1^;
  PartialSum := PartialSum - Byte( PartialSum < AdjustSum2^ );
  PartialSum := PartialSum - AdjustSum2^;
  {$R+}

  // Compute the final checksum value as the sum of the paritial checksum
  // and the file length.
  if ( CheckSum <> nil ) then
    CheckSum^ := PartialSum + Size;
end;

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Import-Enumeration
function EnumerateImportTable( module: PMemoryModule; var Modules : String; DelimiterString : String = ';'; FullPath : Boolean = False ): Boolean; stdcall;
var
  codebase: Pointer;
  directory: PIMAGE_DATA_DIRECTORY;
  importDesc: PIMAGE_IMPORT_DESCRIPTOR;

  FileName : string;
  Path     : String;
  Cnt      : Cardinal;
  FileStr  : PChar;
begin
  codebase := module.codeBase;
  Result := True;

  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_IMPORT );
  if directory.Size = 0 then
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit( True );
    {$ELSE}
    begin
    result := True;
    Exit;
    end;
    {$IFEND}

  importDesc := PIMAGE_IMPORT_DESCRIPTOR( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + directory.VirtualAddress );
  while ( not IsBadReadPtr( importDesc, SizeOf( IMAGE_IMPORT_DESCRIPTOR ) ) ) and ( importDesc.Name <> 0 ) do
    begin
    FileName := String( PAnsiChar( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + importDesc.Name ) );
    if FullPath then
      begin
      // EnvironmentPath
      Cnt := SearchPath( nil, PChar( Filename ), nil, 0, nil, FileStr );
      if ( Cnt > 0 ) then
        begin
        SetLength( Path, Cnt-1 );
        if ( SearchPath( nil, PChar( Filename ), nil, Cnt, PChar( Path ), FileStr ) > 0 ) then
          begin
          if ( Pos( #0, Path ) > 0 ) then
            Path := Copy( Path, 1, Pos( #0, Path )-1 );
          end
        else
          Path := FileName;
        end
      else
        Path := FileName;

      FileName := Path;
      end;

    if ( Modules = '' ) then
      Modules := FileName
    else
      Modules := Modules + DelimiterString + FileName;

    Inc( importDesc );
    end; // while
end;

function MemoryEnumerateImports( data: Pointer; var Modules : string; DelimiterString : String = ';'; FullPath : Boolean = False ): ShortInt;
var
  Code : Pointer;
  module: PMemoryModule;
begin
  module  := nil;
  Modules := '';
  Code    := nil;
  result  := MemoryLoadLibrary_1( data, Code, module );
  if ( result = 0 ) AND Assigned( module ) then
    begin
    if NOT EnumerateImportTable( module, Modules, DelimiterString, FullPath ) then
      result := -99;
    end;

  MemoryFreeLibrary( module );
end;

function MemoryEnumerateImports( ModuleData : Pointer; FileName : String; var Modules : String; DelimiterString : String = ';'; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255 ) : Int64;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
const
  PREFIX_ : Array [ 0..1 ] of String = ( 'api-ms-win-', 'ext-ms-' );
var
  sChecked : String;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  function Recurse( ModuleData : Pointer; FileName : string; RecursePath : String = ''; Level : Word = 0 ) : Cardinal;
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    function ExtractFileName(const FileName: string): string;
      function StrScan(const Str: PChar; Chr: Char): PChar;
      begin
        Result := Str;
        while Result^ <> Chr do
        begin
          if Result^ = #0 then
          begin
            Result := nil;
            Exit;
          end;
          Inc(Result);
        end;
      end;
    const
      Delimiters = '\' + ':'; // PathDelim + DriveDelim
    var
      I: Integer;
      P: PChar;
    begin
      i := Length( FileName );
      P := PChar( Delimiters );
      while i > 1 do
        begin
        if ( FileName[ i-1 ] <> #0 ) and ( StrScan( P, FileName[ i-1 ] ) <> nil ) then
          break;
        Dec(i);
        end;
      if ( i > 1 ) then
        Result := Copy(FileName, I, Length( FileName )-I+1)
      else
        result := FileName;
    end;
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    function AddToList( var List : String; Item : String; DelimiterString : String ) : boolean; overload;
    begin
      result := false;
      if ( Pos( Item + DelimiterString, List ) > 0 ) then
        Exit;
      result := True;
      List := List + Item + DelimiterString;
    end;
   //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  var
    i       : Integer;
    s       : string;
    Data2   : Pointer;
  begin
    result := 0;
    if NOT Assigned( ModuleData ) then
      begin
      if NOT FileExists( FileName ) then
//      if ( FileName = '' ) then
        Exit;
      if ( MemoryEnumerateImportsFile( FileName, s, DelimiterString, True ) <> 0 ) then
        Exit;
      end
    else if ( MemoryEnumerateImports( ModuleData, s, DelimiterString, True ) <> 0 ) then
      Exit;

    if ( Level > 0 ) then
      begin
      if ( RecursePath <> '' ) then
        RecursePath := RecursePath + '>' + ExtractFileName( FileName )
      else
        RecursePath := ExtractFileName( FileName );
      end;

    while ( S <> '' ) do
      begin
      i := Pos( DelimiterString, s );
      if ( i > 0 ) then
        begin
        FileName := Copy( S, 1, i-1 );
        S        := Copy( S, i+Length( DelimiterString ), Length( S )-( i - Length( DelimiterString ) ) );
        end
      else
        begin
        FileName := S;
        S        := '';
        end;

      if ( CompareString( LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar( Copy( FileName, 1, 11 ) ), Length( PREFIX_[ 0 ] ), PChar( PREFIX_[ 0 ] ), Length( PREFIX_[ 0 ] ) ) = 2 ) OR
         ( CompareString( LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar( Copy( FileName, 1, 7 ) ), Length( PREFIX_[ 1 ] ), PChar( PREFIX_[ 1 ] ), Length( PREFIX_[ 1 ] ) ) = 2 ) then
        Continue;

      if FullPath then
        begin
//        if ( RecursePath = '' ) then
          AddToList( Modules, FileName, DelimiterString )
//        else
//          AddToList( Modules, RecursePath + '->' + FileName, DelimiterString );
        end
      else
        begin
//        if ( RecursePath = '' ) then
          AddToList( Modules, ExtractFileName( FileName ), DelimiterString )
//        else
//          AddToList( Modules, RecursePath + '->' + ExtractFileName( FileName ), DelimiterString );
        end;
      Inc( result );

      if FileExists( FileName ) then
        begin
        if ( Level+1 < MaxRecurseDepth ) AND AddToList( sChecked, ExtractFileName( FileName ), ';' ) then
          begin
          Data2 := nil;
          FileToPointer( FileName, PByte( Data2 ) );
          if ( Data2 <> nil ) then
            begin
            Inc( Result, Recurse( Data2, FileName, RecursePath, Level+1 ) );
            FreeMem( Data2 );
            end;
//          else
//            Exit;
          end;
        end;
      end;
  end;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
begin
  Modules  := '';
  sChecked := '';
  result := Recurse( ModuleData, FileName );
end;

//{$IFDEF ALLOW_LOAD_FILES}
function MemoryEnumerateImportsFile( FileName : String; var Modules : String; DelimiterString : String = ';'; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : Int64;
var
  Data : Pointer;
begin
  Data := nil;
  FileToPointer( FileName, PByte( Data ) );
  if Assigned( Data ) then
    begin
    result := MemoryEnumerateImports( Data, FileName, Modules, DelimiterString, FullPath, MaxRecurseDepth );
    FreeMem( Data );
    end
  else
    result := -31;
end;
//{$ENDIF}

{$IFDEF LOAD_FROM_RESOURCE}
function MemoryEnumerateImports( ResourceName : string; FileName : String; var Modules : String; DelimiterString : String = ';'; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : Int64;
const
  RES_TYPE_ = 'DLL'; // RT_RCDATA{10};
var
  HRes   : HRSRC;
  HG     : HGlobal;
  Data   : Pointer;
  Extract: Pointer;
  res    : Int64;
begin
  result := -32;
  HRes := MemoryResourceExists( ResourceName );
  if ( HRes = 0 ) then
    Exit;

  HG := LoadResource( hInstance, HRes );
  if ( HG = 0 ) then
    Exit;
  Data := LockResource( HG );

  Extract := nil;
  res := ExtractPointer( Data, SizeOfResource( hInstance, HRes ), Extract{$IFDEF USE_STREAMS}, Password{$ENDIF} );
  if ( res = 0 ) then
    result := -31
  else if ( res > 0 ) then
    result := MemoryEnumerateImports( Extract, FileName, Modules, DelimiterString, FullPath, MaxRecurseDepth )
  else
    result := res;
  UnlockResource( HG );
  FreeResource( HG );
  if ( Extract <> Data ) then
    ReallocMem( Extract, 0 );
end;
{$ENDIF}

// ~~~ PE bit-depth helpers used by ListMissingModules ~~~
// Reads FileHeader.Machine straight from a mapped/loaded PE image.
// ASize = 0 means "size unknown" (caller passes a full, valid image).
function GetImageMachine( AData : Pointer; ASize : NativeUInt ) : Word;
const
  MAX_LFANEW = 65535;
var
  dos   : PIMAGE_DOS_HEADER;
  ntOff : LongInt;
begin
  result := 0;
  if ( AData = nil ) then
    Exit;
  if ( ASize <> 0 ) AND ( ASize < SizeOf( IMAGE_DOS_HEADER ) ) then
    Exit;
  dos := PIMAGE_DOS_HEADER( AData );
  if ( dos.e_magic <> IMAGE_DOS_SIGNATURE ) then
    Exit;
  ntOff := dos._lfanew;
  if ( ntOff <= 0 ) OR ( ntOff > MAX_LFANEW ) then
    Exit;
  if ( ASize <> 0 ) AND ( NativeUInt( ntOff ) + 6 > ASize ) then
    Exit;
  if ( PDWORD( NativeUInt( AData ) + NativeUInt( ntOff ) )^ <> IMAGE_NT_SIGNATURE ) then
    Exit;
  // FileHeader.Machine sits right after the 4-byte NT signature.
  result := PWord( NativeUInt( AData ) + NativeUInt( ntOff ) + 4 )^;
end;

// Reads FileHeader.Machine from a file on disk (header bytes only).
function GetFileMachine( const AFileName : string ) : Word;
var
  H   : THandle;
  buf : array[ 0..4095 ] of Byte;
  br  : Cardinal;
begin
  result := 0;
  if ( AFileName = '' ) then
    Exit;
  H := CreateFile( PChar( AFileName ), GENERIC_READ,
                   FILE_SHARE_READ OR FILE_SHARE_WRITE OR FILE_SHARE_DELETE,
                   nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
  if ( H = 0 ) OR ( H = INVALID_HANDLE_VALUE ) then
    Exit;
  br := 0;
  if ReadFile( H, buf, SizeOf( buf ), br, nil ) then
    result := GetImageMachine( @buf, br );
  CloseHandle( H );
end;

// Returns the system directory that holds DLLs of the requested architecture,
// as reachable from THIS process (accounts for WOW64 file-system redirection).
// Empty result means "no such directory on this OS".
function SystemDirForMachine( ATargetMachine : Word ) : string;
var
  buf : string;
  win : string;
  n   : Cardinal;
  wow : BOOL;
begin
  result := '';
  case ATargetMachine of
    IMAGE_FILE_MACHINE_I386:
      begin
      // 32-bit system DLLs: SysWOW64 on a 64-bit OS, System32 on a 32-bit OS.
      SetLength( buf, MAX_PATH );
      n := GetSystemWow64Directory( PChar( buf ), MAX_PATH );
      if ( n > 0 ) AND ( n <= MAX_PATH ) then
        begin
        SetLength( buf, n );
        result := buf;
        end
      else
        begin
        SetLength( buf, MAX_PATH );
        n := GetSystemDirectory( PChar( buf ), MAX_PATH );
        if ( n > 0 ) AND ( n <= MAX_PATH ) then
          begin
          SetLength( buf, n );
          result := buf;
          end;
        end;
      end;
    IMAGE_FILE_MACHINE_AMD64:
      begin
      // 64-bit system DLLs live in the real System32.
      SetLength( buf, MAX_PATH );
      n := GetSystemWow64Directory( PChar( buf ), MAX_PATH );
      if ( n = 0 ) then
        Exit; // 32-bit-only OS: there is no 64-bit directory
      wow := False;
      IsWow64Process( GetCurrentProcess, wow );
      if wow then
        begin
        // From a 32-bit (WOW64) process "System32" is redirected to SysWOW64;
        // the "Sysnative" alias reaches the true 64-bit directory.
        SetLength( win, MAX_PATH );
        n := GetWindowsDirectory( PChar( win ), MAX_PATH );
        if ( n = 0 ) OR ( n > MAX_PATH ) then
          Exit;
        SetLength( win, n );
        result := win + '\Sysnative';
        end
      else
        begin
        SetLength( buf, MAX_PATH );
        n := GetSystemDirectory( PChar( buf ), MAX_PATH );
        if ( n > 0 ) AND ( n <= MAX_PATH ) then
          begin
          SetLength( buf, n );
          result := buf;
          end;
        end;
      end;
  end;
end;
// ~~~ end PE bit-depth helpers ~~~

function ListMissingModules( ModuleData : Pointer; FileName : String; var Modules : String; DelimiterString : String = #13#10; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255 ) : Int64;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
const
  PREFIX_ : Array [ 0..1 ] of String = ( 'api-ms-win-', 'ext-ms-' );
var
  sChecked      : String;
  TargetMachine : Word;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  function Recurse( ModuleData : Pointer; FileName : string; RecursePath : String = ''; Level : Word = 0 ) : Cardinal;
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    function ExtractFileName(const FileName: string): string;
      function StrScan(const Str: PChar; Chr: Char): PChar;
      begin
        Result := Str;
        while Result^ <> Chr do
        begin
          if Result^ = #0 then
          begin
            Result := nil;
            Exit;
          end;
          Inc(Result);
        end;
      end;
    const
      Delimiters = '\' + ':'; // PathDelim + DriveDelim
    var
      I: Integer;
      P: PChar;
    begin
      i := Length( FileName );
      P := PChar( Delimiters );
      while i > 1 do
        begin
        if ( FileName[ i-1 ] <> #0 ) and ( StrScan( P, FileName[ i-1 ] ) <> nil ) then
          break;
        Dec(i);
        end;
      if ( i > 1 ) then
        Result := Copy(FileName, I, Length( FileName )-I+1)
      else
        result := FileName;
    end;
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    function AddToList( var List : String; Item : String; DelimiterString : String ) : boolean; overload;
    begin
      result := false;
      if ( Pos( Item + DelimiterString, List ) > 0 ) then
        Exit;
      result := True;
      List := List + Item + DelimiterString;
    end;
   //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  var
    i          : Integer;
    s          : string;
    Data2      : Pointer;
    present    : Boolean;
    depMachine : Word;
    Alt        : string;
  begin
    result := 0;
    if NOT Assigned( ModuleData ) then
      begin
      if NOT FileExists( FileName ) then
//      if ( FileName = '' ) then
        Exit;
      if ( MemoryEnumerateImportsFile( FileName, s, DelimiterString, True ) = 0 ) then
        Exit;
      end
    else if ( MemoryEnumerateImports( ModuleData, s, DelimiterString, True ) <> 0 ) then
      Exit;

    if ( Level > 0 ) then
      begin
      if ( RecursePath <> '' ) then
        RecursePath := RecursePath + '>' + ExtractFileName( FileName )
      else
        RecursePath := ExtractFileName( FileName );
      end;

    while ( S <> '' ) do
      begin
      i := Pos( DelimiterString, s );
      if ( i > 0 ) then
        begin
        FileName := Copy( S, 1, i-1 );
        S        := Copy( S, i+Length( DelimiterString ), Length( S )-( i - Length( DelimiterString ) ) );
        end
      else
        begin
        FileName := S;
        S        := '';
        end;

      if ( CompareString( LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar( Copy( FileName, 1, 11 ) ), Length( PREFIX_[ 0 ] ), PChar( PREFIX_[ 0 ] ), Length( PREFIX_[ 0 ] ) ) = 2 ) OR
         ( CompareString( LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar( Copy( FileName, 1, 7 ) ), Length( PREFIX_[ 1 ] ), PChar( PREFIX_[ 1 ] ), Length( PREFIX_[ 1 ] ) ) = 2 ) then
        Continue;

      // Presence must be architecture-aware: a dependency only counts as satisfied
      // when a file of the SAME bit-depth as the target module exists. SearchPath
      // (done in EnumerateImportTable) resolves relative to THIS process' architecture,
      // so for a target of the opposite bit-depth we re-check the dependency against
      // the architecture-correct system directory before declaring it present.
      present := FileExists( FileName );
      if present AND ( TargetMachine <> 0 ) then
        begin
        depMachine := GetFileMachine( FileName );
        if ( depMachine <> 0 ) AND ( depMachine <> TargetMachine ) then
          begin
          Alt := SystemDirForMachine( TargetMachine );
          if ( Alt <> '' ) then
            Alt := Alt + '\' + ExtractFileName( FileName );
          if ( Alt <> '' ) AND FileExists( Alt ) AND ( GetFileMachine( Alt ) = TargetMachine ) then
            FileName := Alt   // a matching-bitness copy exists elsewhere -> satisfied
          else
            present := False; // only a wrong-bitness copy exists -> effectively missing
          end;
        end;

      if NOT present then
        begin
        if FullPath then
          begin
          if ( RecursePath = '' ) then
            AddToList( Modules, FileName, DelimiterString )
          else
            AddToList( Modules, RecursePath + '->' + FileName, DelimiterString );
          end
        else
          begin
          if ( RecursePath = '' ) then
            AddToList( Modules, ExtractFileName( FileName ), DelimiterString )
          else
            AddToList( Modules, RecursePath + '->' + ExtractFileName( FileName ), DelimiterString );
          end;
        Inc( result );
        end
      else
        begin
        if ( Level+1 < MaxRecurseDepth ) AND AddToList( sChecked, ExtractFileName( FileName ), DelimiterString ) then
          begin
          Data2 := nil;
          FileToPointer( FileName, PByte( Data2 ) );
          if Assigned( Data2 ) then
            begin
            Inc( Result, Recurse( Data2, FileName, RecursePath, Level+1 ) );
            FreeMem( Data2 );
            end;
//          else
//            Exit;
          end;
        end;
      end;
  end;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
begin
  Modules  := '';
  sChecked := '';
  if Assigned( ModuleData ) then
    TargetMachine := GetImageMachine( ModuleData, 0 )
  else
    TargetMachine := GetFileMachine( FileName );
  result := Recurse( ModuleData, FileName );
end;

{$IFDEF ALLOW_LOAD_FILES}
function ListMissingModulesFile( FileName : String; var Modules : String; DelimiterString : String = #13#10; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : Int64;
var
  Data : Pointer;
begin
  Data := nil;
  FileToPointer( FileName, PByte( Data ) );
  if Assigned( Data ) then
    begin
    result := ListMissingModules( Data, FileName, Modules, DelimiterString, FullPath, MaxRecurseDepth );
    FreeMem( Data );
    end
  else
    result := -31;
end;
{$ENDIF}

{$IFDEF LOAD_FROM_RESOURCE}
function ListMissingModules( ResourceName : string; FileName : String; var Modules : String; DelimiterString : String = #13#10; FullPath : Boolean = False; const MaxRecurseDepth : Word = 255{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : Int64;
const
  RES_TYPE_ = 'DLL'; // RT_RCDATA{10};
var
  HRes   : HRSRC;
  HG     : HGlobal;
  Data   : Pointer;
  Extract: Pointer;
  res    : Int64;
begin
  result := -32;
  HRes := MemoryResourceExists( ResourceName );
  if ( HRes = 0 ) then
    Exit;

  HG := LoadResource( hInstance, HRes );
  if ( HG = 0 ) then
    Exit;
  Data := LockResource( HG );
  
  Extract := nil;
  res := ExtractPointer( Data, SizeOfResource( hInstance, HRes ), Extract{$IFDEF USE_STREAMS}, Password{$ENDIF} );
  if ( res = 0 ) then
    result := -31
  else if ( res > 0 ) then
    result := ListMissingModules( Extract, FileName, Modules, DelimiterString, FullPath, MaxRecurseDepth )
  else
    result := res;
  UnlockResource( HG );
  FreeResource( HG );
  if ( Extract <> Data ) then
    ReallocMem( Extract, 0 );
end;
{$ENDIF}

function EnumerateExportTable( module: PMemoryModule; var AExports : String; DelimiterString : String = ';' ): Boolean; stdcall;
var
  codebase: Pointer;
  idx: Integer;
  i: Cardinal;
  nameRef: PDWORD;
  ordinal: PWord;
  exportDir: PIMAGE_EXPORT_DIRECTORY;
  directory: PIMAGE_DATA_DIRECTORY;
//  RVA: DWORD;
//  VA : NativeUInt;
begin
  Result := False;
  if NOT Assigned( module ) then
    Exit;

  codebase := module.codeBase;
  directory := GET_HEADER_DICTIONARY( module, IMAGE_DIRECTORY_ENTRY_EXPORT );
  // no export table found
  if directory.Size = 0 then
    begin
    SetLastError( ERROR_PROC_NOT_FOUND );
    Exit;
    end;

  exportDir := PIMAGE_EXPORT_DIRECTORY( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + directory.VirtualAddress );
  // DLL doesn't export anything
  if ( exportDir.NumberOfNames = 0 ) or ( exportDir.NumberOfFunctions = 0 ) then
    begin
    SetLastError( ERROR_PROC_NOT_FOUND );
    Exit;
    end;

  // search function name in list of exported names
  nameRef := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + {$IF Defined( FPC ) OR ( CompilerVersion < 21 )}Cardinal{$IFEND}( exportDir.AddressOfNames ) );
  ordinal := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + {$IF Defined( FPC ) OR ( CompilerVersion < 21 )}Cardinal{$IFEND}( exportDir.AddressOfNameOrdinals ) );
  for i := 0 to exportDir.NumberOfNames - 1 do
    begin
    idx := ordinal^;
    if ( Cardinal( idx ) > exportDir.NumberOfFunctions ) then
      Break;

//    RVA := PCardinal( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + {$IF Defined( FPC ) OR ( CompilerVersion < 21 )}Cardinal{$IFEND}( exportDir.AddressOfFunctions ) + {$IF Defined( FPC ) OR ( CompilerVersion < 21 )}Cardinal{$IFEND}( idx )*4 )^;
//    VA  := Pointer( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + RVA );

    if ( AExports = '' ) then
      AExports := string( PAnsiChar( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + nameRef^ ) )
    else
      AExports := AExports + DelimiterString + string( PAnsiChar( {$IF Defined( FPC ) OR ( CompilerVersion >= 21 )}PByte{$ELSE}PAnsiChar{$IFEND}( codebase ) + nameRef^ ) );

    Inc( nameRef );
    Inc( ordinal );
    end;

  Result := True;
end;

function MemoryEnumerateExports( ModuleData: Pointer; var AExports : string; DelimiterString : String = ';' ): ShortInt;
var
  Code : Pointer;
  module: PMemoryModule;
begin
  module  := nil;
  AExports := '';
  Code    := nil;
  result  := MemoryLoadLibrary_1( ModuleData, Code, module );
  if ( result = 0 ) AND Assigned( module ) then
    begin
    if NOT EnumerateExportTable( module, AExports, DelimiterString ) then
      result := -99;
    end;

  MemoryFreeLibrary( module );
end;

{$IFDEF ALLOW_LOAD_FILES}
function MemoryEnumerateExportsFile( FileName : String; var AExports : String; DelimiterString : String = ';'{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : ShortInt;
var
  Data : Pointer;
begin
  Data := nil;
  FileToPointer( FileName, PByte( Data ) );
  if Assigned( Data ) then
    begin
    result := MemoryEnumerateExports( Data, AExports, DelimiterString );
    FreeMem( Data );
    end
  else
    result := -31;
end;
{$ENDIF}

{$IFDEF LOAD_FROM_RESOURCE}
function MemoryEnumerateExports( ResourceName : string; var AExports : String; DelimiterString : String = ';'{$IFDEF USE_STREAMS}; Password : string = ''{$ENDIF} ) : ShortInt;
const
  RES_TYPE_ = 'DLL'; // RT_RCDATA{10};
var
  HRes   : HRSRC;
  HG     : HGlobal;
  Data   : Pointer;
  Extract: Pointer;
  res    : Int64;
begin
  result := -32;
  HRes := MemoryResourceExists( ResourceName );
  if ( HRes = 0 ) then
    Exit;

  HG := LoadResource( hInstance, HRes );
  if ( HG = 0 ) then
    Exit;
  Data := LockResource( HG );

  Extract := nil;
  res := ExtractPointer( Data, SizeOfResource( hInstance, HRes ), Extract{$IFDEF USE_STREAMS}, Password{$ENDIF} );
  if ( res = 0 ) then
    result := -31
  else if ( res > 0 ) then
    result := MemoryEnumerateExports( Extract, AExports, DelimiterString )
  else
    result := res;
  UnlockResource( HG );
  FreeResource( HG );
  if ( Extract <> Data ) then
    ReallocMem( Extract, 0 );
end;
{$ENDIF}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{$IFDEF GetModuleHandle}
function MemoryGetModuleHandle( data: Pointer ): PMemoryModule; stdcall; {$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}overload;{$IFEND}
begin
  result := nil;
  if NOT Assigned( ModuleManager ) then
    Exit;
  result := ModuleManager.GetHandle( data );
end;

{$IF Defined( ALLOW_LOAD_FILES ) OR Defined( LOAD_FROM_RESOURCE )}
function MemoryGetModuleHandle( FileName : string{$IFDEF LOAD_FROM_RESOURCE}; IsResource : boolean = False{$ENDIF} ): PMemoryModule; stdcall;
begin
  result := nil;
  if NOT Assigned( ModuleManager ) then
    Exit;
  result := ModuleManager.GetHandle( FileName{$IFDEF LOAD_FROM_RESOURCE}, IsResource{$ENDIF} );
end;
{$IFEND}
{$ENDIF GetModuleHandle}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{$IF Defined( GetModuleHandle ) AND ( NOT Defined( FastMM4 ) AND NOT Defined( FastMM5 ) )}
initialization
  if NOT Assigned( ModuleManager ) then // LoadLibrary called before initialization
    ModuleManager := tModuleManager.Create;
  {$IFDEF UnloadAllOnFinalize}
  InitializationDone := True;
  {$ENDIF UnloadAllOnFinalize}

finalization
  {$IFDEF UnloadAllOnFinalize}
  InitializationDone := False;
  {$ENDIF UnloadAllOnFinalize}
  ModuleManager.free;
  ModuleManager := nil;
{$IFEND}

end.