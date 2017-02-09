unit MemoryModule;

{ * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
  * Memory DLL loading code
  * ------------------------
  *
  * Original C Code
  * Memory DLL loading code
  * Version 0.0.4
  *
  * Copyright (c) 2004-2015 by Joachim Bauch / mail@joachim-bauch.de
  * http://www.joachim-bauch.de
  *
  * The contents of this file are subject to the Mozilla Public License Version
  * 2.0 (the "License"); you may not use this file except in compliance with
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
  * Portions created by Joachim Bauch are Copyright (C) 2004-2015
  * Joachim Bauch. All Rights Reserved.
  *
  * ================== MemoryModule "Conversion to Delphi" ==================
  *
  * Copyright (c) 2015 by Fr0sT / https://github.com/Fr0sT-Brutal
  *
  * Initially based on the code by:
  *   Copyright (c) 2005 - 2006 by Martin Offenwanger / coder@dsplayer.de / http://www.dsplayer.de
  *   Carlo Pasolini / cdpasop@hotmail.it / http://pasotech.altervista.org
  *
  * NOTE
  *   This code is Delphi translation of original C code taken from https://github.com/fancycode/MemoryModule
  *     (commit dc173ca from Mar 1, 2015).
  *   Resource loading and exe loading, custom functions, user data not implemented yet.
  *   Tested under RAD Studio XE2 and XE6 32/64-bit, Lazarus 32-bit
  * }

// To compile under FPC, Delphi mode must be used
// Also define CPUX64 for simplicity
{$IFDEF FPC}
  {$mode delphi}
  {$IFDEF CPU64}
    {$DEFINE CPUX64}
  {$ENDIF}
{$ENDIF}
{$WARN UNSAFE_TYPE OFF}
{$WARN UNSAFE_CODE OFF}

{$IFNDEF FPC}
{$IF CompilerVersion >= 23}
  {$LEGACYIFEND ON}
{$ELSE}
  {$RANGECHECKS OFF} // RangeCheck might cause Internal-Error C1118
{$IFEND}
{$ENDIF}

interface

uses
  Windows;

type
  TMemoryModule = Pointer;

  { ++++++++++++++++++++++++++++++++++++++++++++++++++
    ***  Memory DLL loading functions Declaration  ***
    -------------------------------------------------- }

// return value is nil if function fails
function MemoryLoadLibary(data: Pointer): TMemoryModule; stdcall;
// return value is nil if function fails
function MemoryGetProcAddress(module: TMemoryModule; const name: PAnsiChar): Pointer; stdcall;
// free module
procedure MemoryFreeLibrary(module: TMemoryModule); stdcall;

implementation

  { ++++++++++++++++++++++++++++++++++++++++
    ***  Missing Windows API Definitions ***
    ---------------------------------------- }
type
   _Pointer = Pointer; // Dummy
       
  {$IF NOT DECLARED(IMAGE_BASE_RELOCATION)}
  {$ALIGN 4}
  IMAGE_BASE_RELOCATION = record
    VirtualAddress: DWORD;
    SizeOfBlock: DWORD;
  end;
  {$ALIGN ON}
  PIMAGE_BASE_RELOCATION = ^IMAGE_BASE_RELOCATION;
  {$IFEND}

  // Types that are declared in Pascal-style (ex.: PImageOptionalHeader); redeclaring them in C-style
  {$IF NOT DECLARED(PIMAGE_DATA_DIRECTORY)}
  PIMAGE_DATA_DIRECTORY = ^IMAGE_DATA_DIRECTORY;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_SECTION_HEADER)}
  PIMAGE_SECTION_HEADER = ^IMAGE_SECTION_HEADER;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_EXPORT_DIRECTORY)}
  PIMAGE_EXPORT_DIRECTORY = ^IMAGE_EXPORT_DIRECTORY;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_DOS_HEADER)}
  PIMAGE_DOS_HEADER = ^IMAGE_DOS_HEADER;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_NT_HEADERS)}
  PIMAGE_NT_HEADERS = ^IMAGE_NT_HEADERS;
  {$IFEND}

  {$IF NOT DECLARED(PUINT_PTR)}
  PUINT_PTR = ^UINT_PTR;
  {$IFEND}

  // D7
  {$IF NOT DECLARED(UIntPtr)}
  UIntPtr = Cardinal;
  {$IFEND}

  {$IF NOT DECLARED(UINT16)}
  UINT16 = Word;
  {$IFEND}

  {$IF NOT DECLARED(_IMAGE_TLS_DIRECTORY32)}
  _IMAGE_TLS_DIRECTORY32 = record
    StartAddressOfRawData: DWORD;
    EndAddressOfRawData: DWORD;
    AddressOfIndex: DWORD;             // PDWORD
    AddressOfCallBacks: DWORD;         // PIMAGE_TLS_CALLBACK *
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_TLS_DIRECTORY32)}
  PIMAGE_TLS_DIRECTORY32 = ^_IMAGE_TLS_DIRECTORY32;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_TLS_DIRECTORY)}
  PIMAGE_TLS_DIRECTORY = PIMAGE_TLS_DIRECTORY32;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_TLS_CALLBACK)}
  PIMAGE_TLS_CALLBACK = procedure (DllHandle: Pointer; Reason: DWORD; Reserved: Pointer) stdcall;
  {$IFEND}

  {$IF NOT DECLARED(_IMAGE_IMPORT_DESCRIPTOR)}
  _IMAGE_IMPORT_DESCRIPTOR = record
    case Byte of
      0: (Characteristics: DWORD);          // 0 for terminating null import descriptor
      1: (OriginalFirstThunk: DWORD;        // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
          TimeDateStamp: DWORD;             // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

          ForwarderChain: DWORD;            // -1 if no forwarders
          Name: DWORD;
          FirstThunk: DWORD);                // RVA to IAT (if bound this IAT has actual addresses)
  end;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_IMPORT_DESCRIPTOR)}
  PIMAGE_IMPORT_DESCRIPTOR = ^_IMAGE_IMPORT_DESCRIPTOR;
  {$IFEND}

  {$IF NOT DECLARED(_IMAGE_IMPORT_BY_NAME)}
  _IMAGE_IMPORT_BY_NAME = record
    Hint: Word;
    Name: array[0..0] of Byte;
  end;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_IMPORT_BY_NAME)}
  PIMAGE_IMPORT_BY_NAME = ^_IMAGE_IMPORT_BY_NAME;
  {$IFEND}

  {$IF NOT DECLARED(_IMAGE_IMPORT_DESCRIPTOR)}
  _IMAGE_IMPORT_DESCRIPTOR = record
    case Byte of
      0: (Characteristics: DWORD);          // 0 for terminating null import descriptor
      1: (OriginalFirstThunk: DWORD;        // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
          TimeDateStamp: DWORD;             // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

          ForwarderChain: DWORD;            // -1 if no forwarders
          Name: DWORD;
          FirstThunk: DWORD);                // RVA to IAT (if bound this IAT has actual addresses)
  end;
  {$IFEND}

  {$IF NOT DECLARED(IMAGE_IMPORT_DESCRIPTOR)}
  IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR;
  {$IFEND}

  {$IF NOT DECLARED(LPSYSTEM_INFO)}
  LPSYSTEM_INFO = ^SYSTEM_INFO;
  {$IFEND}

// Missing constants
const
  IMAGE_SIZEOF_BASE_RELOCATION = 8;
  IMAGE_REL_BASED_ABSOLUTE = 0;
  IMAGE_REL_BASED_HIGHLOW = 3;
  IMAGE_REL_BASED_DIR64 = 10;
{$IF NOT Defined( FPC ) AND ( CompilerVersion < 23 )}
  IMAGE_ORDINAL_FLAG64 = UInt64($8000000000000000);
  IMAGE_ORDINAL_FLAG32 = LongWord($80000000);
  IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32;
  HEAP_ZERO_MEMORY   = $00000008;
{$IFEND}

// Things that are incorrectly defined at least up to XE6 (miss x64 mapping)
{$IFDEF CPUX64}
type
  PIMAGE_TLS_DIRECTORY = PIMAGE_TLS_DIRECTORY64;
const
  IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64;
{$ENDIF}

type
{ +++++++++++++++++++++++++++++++++++++++++++++++
  ***  Internal MemoryModule Type Definition  ***
  ----------------------------------------------- }
  TMemoryModuleRec = record
    headers: PIMAGE_NT_HEADERS;
    codeBase: Pointer;
    modules: array of HMODULE;
    numModules: Integer;
    initialized: Boolean;
    isRelocated: Boolean;
    pageSize: DWORD;
  end;
  PMemoryModule = ^TMemoryModuleRec;

  TDllEntryProc = function(hinstDLL: HINST; fdwReason: DWORD; lpReserved: Pointer): BOOL; stdcall;

  TSectionFinalizeData = record
    address: Pointer;
    alignedAddress: Pointer;
    size: DWORD;
    characteristics: DWORD;
    last: Boolean;
  end;

// Explicitly export these functions to allow hooking of their origins
function GetProcAddress_Internal(hModule: HMODULE; lpProcName: LPCSTR): FARPROC; stdcall; external kernel32 name 'GetProcAddress';
function LoadLibraryA_Internal(lpLibFileName: LPCSTR): HMODULE; stdcall; external kernel32 name 'LoadLibraryA';
function FreeLibrary_Internal(hLibModule: HMODULE): BOOL; stdcall; external kernel32 name 'FreeLibrary';

{$IF NOT Defined( FPC ) AND ( CompilerVersion < 23 )}
procedure GetNativeSystemInfo(lpSystemInfo: LPSYSTEM_INFO); stdcall; external kernel32 name 'GetNativeSystemInfo';
{$IFEND}

// Just an imitation to allow using try-except block. DO NOT try to handle this
// like "on E do ..." !
procedure Abort;
begin
  raise TObject.Create;
end;

// Copy from SysUtils to get rid of this unit
function StrComp(const Str1, Str2: PAnsiChar): Integer;
var
  P1, P2: PAnsiChar;
begin
  P1 := Str1;
  P2 := Str2;
  while True do
    begin
    if (P1^ <> P2^) or (P1^ = #0) then
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      Exit(Ord(P1^) - Ord(P2^));
      {$ELSE}
      begin
      result := Ord(P1^) - Ord(P2^);
      Exit;
      end;
      {$IFEND}
    Inc(P1);
    Inc(P2);
    end;
end;

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***                Missing WinAPI macros          ***
    ----------------------------------------------------- }

{$IF NOT DECLARED(IMAGE_ORDINAL)}
//  #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
//  #define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
function IMAGE_ORDINAL(Ordinal: NativeUInt): Word; {$IF Defined( FPC ) OR ( CompilerVersion >= 22 )}inline;{$IFEND}
begin
  Result := Ordinal and $FFFF;
end;
{$IFEND}

{$IF NOT DECLARED(IMAGE_SNAP_BY_ORDINAL)}
//  IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
//  IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
function IMAGE_SNAP_BY_ORDINAL(Ordinal: NativeUInt): Boolean; {$IF Defined( FPC ) OR ( CompilerVersion >= 22 )}inline;{$IFEND}
begin
  Result := ((Ordinal and IMAGE_ORDINAL_FLAG) <> 0);
end;
{$IFEND}

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***                 Helper functions              ***
    ----------------------------------------------------- }

function GET_HEADER_DICTIONARY(module: PMemoryModule; idx: Integer): PIMAGE_DATA_DIRECTORY;
begin
  Result := PIMAGE_DATA_DIRECTORY(@(module.headers.OptionalHeader.DataDirectory[idx]));
end;

function ALIGN_DOWN(address: Pointer; alignment: DWORD): Pointer;
begin
  Result := Pointer(UIntPtr(address) and not (alignment - 1));
end;

{$IF NOT DECLARED(IMAGE_FIRST_SECTION)}
function IMAGE_FIRST_SECTION( NtHeader: PIMAGE_NT_HEADERS ): PImageSectionHeader;
var
  OptionalHeaderAddr: PByte;
begin
  OptionalHeaderAddr := @NtHeader^.OptionalHeader;
  Inc(OptionalHeaderAddr, NtHeader^.FileHeader.SizeOfOptionalHeader);
  Result := PImageSectionHeader(OptionalHeaderAddr);
end;
{$IFEND}

function CopySections(data: Pointer; old_headers: PIMAGE_NT_HEADERS; module: PMemoryModule): Boolean;
var
  i, size: Integer;
  codebase: Pointer;
  dest: Pointer;
  section: PIMAGE_SECTION_HEADER;
begin
  codebase := module.codeBase;
  {$IF NOT Defined( FPC ) AND ( CompilerVersion < 23 )}
  section := PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(module.headers));
  {$ELSE}
  section := PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(module.headers{$IFNDEF FPC}^{$ENDIF}));
  {$IFEND}
  for i := 0 to module.headers.FileHeader.NumberOfSections - 1 do
    begin
    // section doesn't contain data in the dll itself, but may define
    // uninitialized data
    if section.SizeOfRawData = 0 then
      begin
      size := old_headers.OptionalHeader.SectionAlignment;
      if size > 0 then
        begin
        dest := VirtualAlloc(
                             {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
                             PByte(codebase) + section.VirtualAddress,
                             {$ELSE}
                             PAnsiChar(codebase) + section.VirtualAddress,
                             {$IFEND}
                             size,
                             MEM_COMMIT,
                             PAGE_READWRITE);
        if dest = nil then
          {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
          Exit(false);
          {$ELSE}
          begin
          result := false;
          Exit;
          end;
          {$IFEND}

        // Always use position from file to support alignments smaller
        // than page size.
        {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
        dest := PByte(codebase) + section.VirtualAddress;
        {$ELSE}
        dest := PAnsiChar(codebase) + section.VirtualAddress;
        {$IFEND}
        section.Misc.PhysicalAddress := DWORD(dest);
        ZeroMemory(dest, size);
        end;
      // section is empty
      Inc(section);
      Continue;
      end; // if

    // commit memory block and copy data from dll
    dest := VirtualAlloc(
                         {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
                         PByte(codebase) + section.VirtualAddress,
                         {$ELSE}
                         PAnsiChar(codebase) + section.VirtualAddress,
                         {$IFEND}
                         section.SizeOfRawData,
                         MEM_COMMIT,
                         PAGE_READWRITE);
    if dest = nil then
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      Exit(false);
      {$ELSE}
      begin
      result := false;
      Exit;
      end;
      {$IFEND}

    // Always use position from file to support alignments smaller
    // than page size.
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    dest := PByte(codebase) + section.VirtualAddress;
    CopyMemory(dest, PByte(data) + section.PointerToRawData, section.SizeOfRawData);
    {$ELSE}
    dest := PAnsiChar(codebase) + section.VirtualAddress;
    CopyMemory(dest, PAnsiChar(data) + section.PointerToRawData, section.SizeOfRawData);
    {$IFEND}
    section.Misc.PhysicalAddress := DWORD(dest);
    Inc(section);
    end; // for

  Result := True;
end;

// Protection flags for memory pages (Executable, Readable, Writeable)
const
  ProtectionFlags: array[Boolean, Boolean, Boolean] of DWORD =
  (
    (
        // not executable
        (PAGE_NOACCESS, PAGE_WRITECOPY),
        (PAGE_READONLY, PAGE_READWRITE)
    ),
    (
        // executable
        (PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY),
        (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
    )
);

function GetRealSectionSize(module: PMemoryModule; section: PIMAGE_SECTION_HEADER): DWORD;
begin
  Result := section.SizeOfRawData;
  if Result = 0 then
    if (section.Characteristics and IMAGE_SCN_CNT_INITIALIZED_DATA) <> 0 then
      Result := module.headers.OptionalHeader.SizeOfInitializedData
    else if (section.Characteristics and IMAGE_SCN_CNT_UNINITIALIZED_DATA) <> 0 then
      Result := module.headers.OptionalHeader.SizeOfUninitializedData;
end;

function FinalizeSection(module: PMemoryModule; const sectionData: TSectionFinalizeData): Boolean;
var
  protect, oldProtect: DWORD;
  executable, readable, writeable: Boolean;
begin
  if sectionData.size = 0 then
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit(True);
    {$ELSE}
    begin
    result := True;
    Exit;
    end;
    {$IFEND}

  if (sectionData.characteristics and IMAGE_SCN_MEM_DISCARDABLE) <> 0 then
    begin
    // section is not needed any more and can safely be freed
    if (sectionData.address = sectionData.alignedAddress) and
       ( sectionData.last or
         (module.headers.OptionalHeader.SectionAlignment = module.pageSize) or
         (sectionData.size mod module.pageSize = 0)
       ) then
         // Only allowed to decommit whole pages
         VirtualFree(sectionData.address, sectionData.size, MEM_DECOMMIT);
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit(True);
    {$ELSE}
    result := True;
    Exit;
    {$IFEND}
    end;

  // determine protection flags based on characteristics
  executable := (sectionData.characteristics and IMAGE_SCN_MEM_EXECUTE) <> 0;
  readable   := (sectionData.characteristics and IMAGE_SCN_MEM_READ) <> 0;
  writeable  := (sectionData.characteristics and IMAGE_SCN_MEM_WRITE) <> 0;
  protect := ProtectionFlags[executable][readable][writeable];
  if (sectionData.characteristics and IMAGE_SCN_MEM_NOT_CACHED) <> 0 then
    protect := protect or PAGE_NOCACHE;

  // change memory access flags
  Result := VirtualProtect(sectionData.address, sectionData.size, protect, oldProtect);
end;

function FinalizeSections(module: PMemoryModule): Boolean;
var
  i: Integer;
  section: PIMAGE_SECTION_HEADER;
  imageOffset: UIntPtr;
  sectionData: TSectionFinalizeData;
  sectionAddress, alignedAddress: Pointer;
  sectionSize: DWORD;
begin
  {$IF CompilerVersion < 23}
  section := PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(module.headers));
  {$ELSE}
  section := PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(module.headers{$IFNDEF FPC}^{$ENDIF}));
  {$IFEND}
  {$IFDEF CPUX64}
  imageOffset := (NativeUInt(module.codeBase) and $ffffffff00000000);
  {$ELSE}
  imageOffset := 0;
  {$ENDIF}

  sectionData.address := Pointer(UIntPtr(section.Misc.PhysicalAddress) or imageOffset);
  sectionData.alignedAddress := ALIGN_DOWN(sectionData.address, module.pageSize);
  sectionData.size := GetRealSectionSize(module, section);
  sectionData.characteristics := section.Characteristics;
  sectionData.last := False;
  Inc(section);

  // loop through all sections and change access flags

  for i := 1 to module.headers.FileHeader.NumberOfSections - 1 do
    begin
    sectionAddress := Pointer(UIntPtr(section.Misc.PhysicalAddress) or imageOffset);
    alignedAddress := ALIGN_DOWN(sectionData.address, module.pageSize);
    sectionSize := GetRealSectionSize(module, section);
    // Combine access flags of all sections that share a page
    // TODO(fancycode): We currently share flags of a trailing large section
    //   with the page of a first small section. This should be optimized.
    if (sectionData.alignedAddress = alignedAddress) or
        {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
       (PByte(sectionData.address) + sectionData.size > PByte(alignedAddress)) then
        {$ELSE}
       (PAnsiChar(sectionData.address) + sectionData.size > PAnsiChar(alignedAddress)) then
        {$IFEND}
      begin
      // Section shares page with previous
      if (section.Characteristics and IMAGE_SCN_MEM_DISCARDABLE = 0) or
         (sectionData.Characteristics and IMAGE_SCN_MEM_DISCARDABLE = 0) then
        sectionData.characteristics := (sectionData.characteristics or section.Characteristics) and not IMAGE_SCN_MEM_DISCARDABLE
      else
        sectionData.characteristics := sectionData.characteristics or section.Characteristics;

      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      sectionData.size := PByte(sectionAddress) + sectionSize - PByte(sectionData.address);
      {$ELSE}
      sectionData.size := PAnsiChar(sectionAddress) + sectionSize - PAnsiChar(sectionData.address);
      {$IFEND}

      Inc(section);
      Continue;
      end;

    if not FinalizeSection(module, sectionData) then
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      Exit(false);
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

    Inc(section);
    end; // for

  sectionData.last := True;
  if not FinalizeSection(module, sectionData) then
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit(false);
    {$ELSE}
    begin
    result := false;
    Exit;
    end;
    {$IFEND}

  Result := True;
end;

function ExecuteTLS(module: PMemoryModule): Boolean;
var
  codeBase: Pointer;
  directory: PIMAGE_DATA_DIRECTORY;
  tls: PIMAGE_TLS_DIRECTORY;
  callback: PPointer; // =^PIMAGE_TLS_CALLBACK;

  // TLS callback pointers are VA's (ImageBase included) so if the module resides at
  // the other ImageBage they become invalid. This routine relocates them to the
  // actual ImageBase.
  // The case seem to happen with DLLs only and they rarely use TLS callbacks.
  // Moreover, they probably don't work at all when using DLL dynamically which is
  // the case in our code.
  function FixPtr(OldPtr: Pointer): Pointer;
  begin
    Result := Pointer(NativeInt(OldPtr) - module.headers.OptionalHeader.ImageBase + NativeInt(codeBase));
  end;
begin
  Result := True;
  codeBase := module.codeBase;

  directory := GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
  if directory.VirtualAddress = 0 then
    Exit;

  {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
  tls := PIMAGE_TLS_DIRECTORY(PByte(codeBase) + directory.VirtualAddress);
  {$ELSE}
  tls := PIMAGE_TLS_DIRECTORY(PAnsiChar(codeBase) + directory.VirtualAddress);
  {$IFEND}

  // Delphi syntax is quite awkward when dealing with proc pointers so we have to
  // use casts to untyped pointers
  callback := Pointer(tls.AddressOfCallBacks);
  if callback <> nil then
    begin
    callback := FixPtr(callback);
    while callback^ <> nil do
      begin
      PIMAGE_TLS_CALLBACK(FixPtr(callback^))(codeBase, DLL_PROCESS_ATTACH, nil);
      Inc(callback);
      end;
    end;
end;

function PerformBaseRelocation(module: PMemoryModule; delta: NativeInt): Boolean;
var
  i: Cardinal;
  codebase: Pointer;
  directory: PIMAGE_DATA_DIRECTORY;
  relocation: PIMAGE_BASE_RELOCATION;
  dest: Pointer;
  relInfo: ^UInt16;
  patchAddrHL: PDWORD;
  {$IFDEF CPUX64}
  patchAddr64: PULONGLONG;
  {$ENDIF}
  relType, offset: Integer;
begin
  codebase := module.codeBase;
  directory := GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
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
  relocation := PIMAGE_BASE_RELOCATION(PByte(codebase) + directory.VirtualAddress);
  {$ELSE}
  relocation := PIMAGE_BASE_RELOCATION(PAnsiChar(codebase) + directory.VirtualAddress);
  {$IFEND}

  while relocation.VirtualAddress > 0 do
    begin
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    dest := Pointer(PByte(codebase) + relocation.VirtualAddress);
    relInfo := Pointer(PByte(relocation) + IMAGE_SIZEOF_BASE_RELOCATION);
    {$ELSE}
    dest := Pointer(PAnsiChar(codebase) + relocation.VirtualAddress);
    relInfo := Pointer(PAnsiChar(relocation) + IMAGE_SIZEOF_BASE_RELOCATION);
    {$IFEND}

    for i := 0 to Trunc(((relocation.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2)) - 1 do
      begin
      // the upper 4 bits define the type of relocation
      relType := relInfo^ shr 12;
      // the lower 12 bits define the offset
      offset := relInfo^ and $FFF;

      case relType of
        IMAGE_REL_BASED_ABSOLUTE:
          // skip relocation
          ;
        IMAGE_REL_BASED_HIGHLOW:
            begin
            // change complete 32 bit address
            {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
            patchAddrHL := Pointer(PByte(dest) + offset);
            {$ELSE}
            patchAddrHL := Pointer(PAnsiChar(dest) + offset);
            {$IFEND}

            Inc(patchAddrHL^, delta);
            end;

        {$IFDEF CPUX64}
        IMAGE_REL_BASED_DIR64:
            begin
            patchAddr64 := Pointer(PByte(dest) + offset);
            Inc(patchAddr64^, delta);
            end;
        {$ENDIF}
      end;

      Inc(relInfo);
      end; // for

    // advance to next relocation block
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    relocation := PIMAGE_BASE_RELOCATION(PByte(relocation) + relocation.SizeOfBlock);
    {$ELSE}
    relocation := PIMAGE_BASE_RELOCATION(PAnsiChar(relocation) + relocation.SizeOfBlock);
    {$IFEND}
    end; // while

  Result := True;
end;

function BuildImportTable(module: PMemoryModule): Boolean; stdcall;
var
  codebase: Pointer;
  directory: PIMAGE_DATA_DIRECTORY;
  importDesc: PIMAGE_IMPORT_DESCRIPTOR;
  thunkRef: PUINT_PTR;
  funcRef: ^FARPROC;
  handle: HMODULE;
  thunkData: PIMAGE_IMPORT_BY_NAME;
begin
  codebase := module.codeBase;
  Result := True;

  directory := GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
  if directory.Size = 0 then
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    Exit(True);
    {$ELSE}
    begin
    result := True;
    Exit;
    end;
    {$IFEND}

  {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
  importDesc := PIMAGE_IMPORT_DESCRIPTOR(PByte(codebase) + directory.VirtualAddress);
  {$ELSE}
  importDesc := PIMAGE_IMPORT_DESCRIPTOR(PAnsiChar(codebase) + directory.VirtualAddress);
  {$IFEND}

  while (not IsBadReadPtr(importDesc, SizeOf(IMAGE_IMPORT_DESCRIPTOR))) and (importDesc.Name <> 0) do
    begin
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    handle := LoadLibraryA_Internal(PAnsiChar(PByte(codebase) + importDesc.Name));
    {$ELSE}
    handle := LoadLibraryA_Internal(PAnsiChar(PAnsiChar(codebase) + importDesc.Name));
    {$IFEND}

    if handle = 0 then
      begin
      SetLastError(ERROR_MOD_NOT_FOUND);
      Result := False;
      Break;
      end;

    try
      SetLength(module.modules, module.numModules + 1);
    except
      FreeLibrary_Internal(handle);
      SetLastError(ERROR_OUTOFMEMORY);
      Result := False;
      Break;
    end;
    module.modules[module.numModules] := handle;
    Inc(module.numModules);

    if importDesc.OriginalFirstThunk <> 0 then
      begin
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      thunkRef := Pointer(PByte(codebase) + importDesc.OriginalFirstThunk);
      funcRef := Pointer(PByte(codebase) + importDesc.FirstThunk);
      {$ELSE}
      thunkRef := Pointer(PAnsiChar(codebase) + importDesc.OriginalFirstThunk);
      funcRef := Pointer(PAnsiChar(codebase) + importDesc.FirstThunk);
      {$IFEND}
      end
    else
      begin
      // no hint table
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      thunkRef := Pointer(PByte(codebase) + importDesc.FirstThunk);
      funcRef := Pointer(PByte(codebase) + importDesc.FirstThunk);
      {$ELSE}
      thunkRef := Pointer(PAnsiChar(codebase) + importDesc.FirstThunk);
      funcRef := Pointer(PAnsiChar(codebase) + importDesc.FirstThunk);
      {$IFEND}
      end;

    while thunkRef^ <> 0 do
      begin
      if IMAGE_SNAP_BY_ORDINAL(thunkRef^) then
        funcRef^ := GetProcAddress_Internal(handle, PAnsiChar(IMAGE_ORDINAL(thunkRef^)))
      else
        begin
        {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
        thunkData := PIMAGE_IMPORT_BY_NAME(PByte(codebase) + thunkRef^);
        {$ELSE}
        thunkData := PIMAGE_IMPORT_BY_NAME(PAnsiChar(codebase) + thunkRef^); // RangeCheck causing Internal-Error C1118
        {$IFEND}
        funcRef^ := GetProcAddress_Internal(handle, PAnsiChar(@(thunkData.Name)));
        end;
      if funcRef^ = nil then
        begin
        Result := False;
        Break;
        end;
      Inc(funcRef);
      Inc(thunkRef);
      end; // while

    if not Result then
      begin
      FreeLibrary_Internal(handle);
      SetLastError(ERROR_PROC_NOT_FOUND);
      Break;
      end;

    Inc(importDesc);
    end; // while
end;

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***  Memory DLL loading functions Implementation  ***
    ----------------------------------------------------- }

function MemoryLoadLibary(data: Pointer): TMemoryModule; stdcall;
var
  dos_header: PIMAGE_DOS_HEADER;
  old_header: PIMAGE_NT_HEADERS;
  code, headers: Pointer;
  locationdelta: NativeInt;
  sysInfo: SYSTEM_INFO;
  DllEntry: TDllEntryProc;
  successfull: Boolean;
  module: PMemoryModule;
begin
  Result := nil;
  module := nil;

  try
    dos_header := PIMAGE_DOS_HEADER(data);
    if (dos_header.e_magic <> IMAGE_DOS_SIGNATURE) then
      begin
      SetLastError(ERROR_BAD_EXE_FORMAT);
      Exit;
      end;

    // old_header = (PIMAGE_NT_HEADERS)&((const unsigned char * )(data))[dos_header->e_lfanew];
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    old_header := PIMAGE_NT_HEADERS(PByte(data) + dos_header._lfanew);
    {$ELSE}
    old_header := PIMAGE_NT_HEADERS(PAnsiChar(data) + dos_header._lfanew);
    {$IFEND}

    if old_header.Signature <> IMAGE_NT_SIGNATURE then
      begin
      SetLastError(ERROR_BAD_EXE_FORMAT);
      Exit;
      end;

    {$IFDEF CPUX64}
    if old_header.FileHeader.Machine <> IMAGE_FILE_MACHINE_AMD64 then
    {$ELSE}
    if old_header.FileHeader.Machine <> IMAGE_FILE_MACHINE_I386 then
    {$ENDIF}
      begin
      SetLastError(ERROR_BAD_EXE_FORMAT);
      Exit;
      end;

    if (old_header.OptionalHeader.SectionAlignment and 1) <> 0 then
      begin
      // Only support section alignments that are a multiple of 2
      SetLastError(ERROR_BAD_EXE_FORMAT);
      Exit;
      end;

    // reserve memory for image of library
    // XXX: is it correct to commit the complete memory region at once?
    //      calling DllEntry raises an exception if we don't...
    code := VirtualAlloc(Pointer(old_header.OptionalHeader.ImageBase),
                         old_header.OptionalHeader.SizeOfImage,
                         MEM_RESERVE or MEM_COMMIT,
                         PAGE_READWRITE);
    if code = nil then
      begin
      // try to allocate memory at arbitrary position
      code := VirtualAlloc(nil,
                           old_header.OptionalHeader.SizeOfImage,
                           MEM_RESERVE or MEM_COMMIT,
                           PAGE_READWRITE);
      if code = nil then
        begin
        SetLastError(ERROR_OUTOFMEMORY);
        Exit;
        end;
      end;

    module := PMemoryModule(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeOf(TMemoryModuleRec)));
    if module = nil then
      begin
      VirtualFree(code, 0, MEM_RELEASE);
      SetLastError(ERROR_OUTOFMEMORY);
      Exit;
      end;

    // memory is zeroed by HeapAlloc
    module.codeBase := code;

    {$IF CompilerVersion >= 23}
    GetNativeSystemInfo({$IFDEF FPC}@{$ENDIF}sysInfo);
    {$ELSE}
    GetNativeSystemInfo(@sysInfo);
    {$IFEND}
    module.pageSize := sysInfo.dwPageSize;

    // commit memory for headers
    headers := VirtualAlloc(code,
                            old_header.OptionalHeader.SizeOfHeaders,
                            MEM_COMMIT,
                            PAGE_READWRITE);

    // copy PE header to code
    CopyMemory(headers, dos_header, old_header.OptionalHeader.SizeOfHeaders);
    // result->headers = (PIMAGE_NT_HEADERS)&((const unsigned char *)(headers))[dos_header->e_lfanew];
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    module.headers := PIMAGE_NT_HEADERS(PByte(headers) + dos_header._lfanew);
    {$ELSE}
    module.headers := PIMAGE_NT_HEADERS(PAnsiChar(headers) + dos_header._lfanew);
    {$IFEND}

    // copy sections from DLL file block to new memory location
    if not CopySections(data, old_header, module) then
      Abort;

    // adjust base address of imported data
    locationdelta := NativeInt(code) - old_header.OptionalHeader.ImageBase;
    if locationdelta <> 0 then
      module.isRelocated := PerformBaseRelocation(module, locationdelta)
    else
      module.isRelocated := True;

    // load required dlls and adjust function table of imports
    if not BuildImportTable(module) then
      Abort;

    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    if not FinalizeSections(module) then
      Abort;

    // TLS callbacks are executed BEFORE the main loading
    if not ExecuteTLS(module) then
      Abort;

    // get entry point of loaded library
    if module.headers.OptionalHeader.AddressOfEntryPoint <> 0 then
      begin
      {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
      @DllEntry := Pointer(PByte(code) + module.headers.OptionalHeader.AddressOfEntryPoint);
      {$ELSE}
      @DllEntry := Pointer(PAnsiChar(code) + module.headers.OptionalHeader.AddressOfEntryPoint);
      {$IFEND}

      // notify library about attaching to process
      successfull := DllEntry(HINST(code), DLL_PROCESS_ATTACH, nil);
      if not successfull then
        begin
        SetLastError(ERROR_DLL_INIT_FAILED);
        Abort;
        end;
      module.initialized := True;
      end;

    Result := module;
  except
    // cleanup
    MemoryFreeLibrary(module);
    Exit;
  end;
end;

function MemoryGetProcAddress(module: TMemoryModule; const name: PAnsiChar): Pointer; stdcall;
var
  codebase: Pointer;
  idx: Integer;
  i: DWORD;
  nameRef: PDWORD;
  ordinal: PWord;
  exportDir: PIMAGE_EXPORT_DIRECTORY;
  directory: PIMAGE_DATA_DIRECTORY;
  temp: PDWORD;
  mmodule: PMemoryModule;
begin
  Result := nil;
  mmodule := PMemoryModule(module);

  codebase := mmodule.codeBase;
  directory := GET_HEADER_DICTIONARY(mmodule, IMAGE_DIRECTORY_ENTRY_EXPORT);
  // no export table found
  if directory.Size = 0 then
  begin
    SetLastError(ERROR_PROC_NOT_FOUND);
    Exit;
  end;

  {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
  exportDir := PIMAGE_EXPORT_DIRECTORY(PByte(codebase) + directory.VirtualAddress);
  {$ELSE}
  exportDir := PIMAGE_EXPORT_DIRECTORY(PAnsiChar(codebase) + directory.VirtualAddress);
  {$IFEND}

  // DLL doesn't export anything
  if (exportDir.NumberOfNames = 0) or (exportDir.NumberOfFunctions = 0) then
  begin
    SetLastError(ERROR_PROC_NOT_FOUND);
    Exit;
  end;

  // search function name in list of exported names
  {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
  nameRef := Pointer(PByte(codebase) + exportDir.AddressOfNames);
  ordinal := Pointer(PByte(codebase) + exportDir.AddressOfNameOrdinals);
  {$ELSE}
  nameRef := Pointer(PAnsiChar(codebase) + Cardinal(exportDir.AddressOfNames));
  ordinal := Pointer(PAnsiChar(codebase) + Cardinal(exportDir.AddressOfNameOrdinals));
  {$IFEND}
  idx := -1;
  for i := 0 to exportDir.NumberOfNames - 1 do
    begin
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    if StrComp(name, PAnsiChar(PByte(codebase) + nameRef^)) = 0 then
    {$ELSE}
    if StrComp(name, PAnsiChar(PAnsiChar(codebase) + nameRef^)) = 0 then
    {$IFEND}
      begin
      idx := ordinal^;
      Break;
      end;
    Inc(nameRef);
    Inc(ordinal);
    end;

  // exported symbol not found
  if (idx = -1) then
    begin
    SetLastError(ERROR_PROC_NOT_FOUND);
    Exit;
    end;

  // name <-> ordinal number don't match
  if (DWORD(idx) > exportDir.NumberOfFunctions) then
    begin
    SetLastError(ERROR_PROC_NOT_FOUND);
    Exit;
    end;

  // AddressOfFunctions contains the RVAs to the "real" functions     {}
  {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
  temp := Pointer(PByte(codebase) + exportDir.AddressOfFunctions + idx*4);
  Result := Pointer(PByte(codebase) + temp^);
  {$ELSE}
  temp := Pointer(PAnsiChar(codebase) + Cardinal( exportDir.AddressOfFunctions ) + Cardinal( idx )*4);
  Result := Pointer(PAnsiChar(codebase) + temp^);
  {$IFEND}
end;

procedure MemoryFreeLibrary(module: TMemoryModule); stdcall;
var
  i: Integer;
  DllEntry: TDllEntryProc;
  mmodule: PMemoryModule;
begin
  if module = nil then Exit;

  mmodule := PMemoryModule(module);

  if mmodule.initialized then
    begin
    // notify library about detaching from process
    {$IF Defined( FPC ) OR ( CompilerVersion >= 20 )}
    @DllEntry := Pointer(PByte(mmodule.codeBase) + mmodule.headers.OptionalHeader.AddressOfEntryPoint);
    {$ELSE}
    @DllEntry := Pointer(PAnsiChar(mmodule.codeBase) + mmodule.headers.OptionalHeader.AddressOfEntryPoint);
    {$IFEND}
    DllEntry(HINST(mmodule.codeBase), DLL_PROCESS_DETACH, nil);
    end;

  if Length(mmodule.modules) <> 0 then
    begin
    // free previously opened libraries
    for i := 0 to mmodule.numModules - 1 do
      if mmodule.modules[i] <> 0 then
        FreeLibrary_Internal(mmodule.modules[i]);

    SetLength(mmodule.modules, 0);
    end;

  if mmodule.codeBase <> nil then
    // release memory of library
    VirtualFree(mmodule.codeBase, 0, MEM_RELEASE);

  HeapFree(GetProcessHeap(), 0, mmodule);
end;

end. 
