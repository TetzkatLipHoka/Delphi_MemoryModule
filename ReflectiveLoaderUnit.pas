unit ReflectiveLoaderUnit;

{ Faithful Delphi translation of Stephen Fewer's "Reflective DLL Injection" ReflectiveLoader,
  (unit named ReflectiveLoaderUnit, not ReflectiveLoader, only because Delphi disallows a top-level
  function sharing its enclosing unit's exact name - the exported function below is still named
  exactly ReflectiveLoader, matching upstream.)
  ported from MemoryModulePP-master\MemoryModule\ReflectiveDLLInjection.h / ReflectiveLoader.h /
  ReflectiveLoader.c (themselves bundled, unmodified beyond attribution, in that upstream repo).
  Standalone / NOT used by or wired into MemoryModule.pas - see TODO.md item 4's entry 5. Kept only
  as a low-priority reference "bonus", matching its own role in the upstream repo (bundled
  alongside MemoryModulePP's actual loader, not part of it).

  ============================== Original license (preserved) ==============================
  Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
  All rights reserved.

  Redistribution and use in source and binary forms, with or without modification, are permitted
  provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright notice, this list of
  conditions and the following disclaimer.

      * Redistributions in binary form must reproduce the above copyright notice, this list of
  conditions and the following disclaimer in the documentation and/or other materials provided
  with the distribution.

      * Neither the name of Harmony Security nor the names of its contributors may be used to
  endorse or promote products derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
  FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
  =============================================================================================

  WHAT THIS IS: a hash-based, self-locating PE loader meant to be exported (as ReflectiveLoader)
  from within a target DLL. An external injector writes that DLL's raw, unmapped bytes into
  another process (no LoadLibrary involved - none of this project's MemoryLoadLibrary machinery
  applies here either) and starts a remote thread directly at ReflectiveLoader's own code address
  (computed from the DLL's own export table), passing a pointer to the start of those raw bytes as
  the sole argument. Because nothing has loaded this DLL through the normal OS path yet,
  ReflectiveLoader's own code cannot rely on an import table (none was ever resolved) - it locates
  kernel32.dll/ntdll.dll by walking the PEB's module list manually and resolves LoadLibraryA /
  GetProcAddress / VirtualAlloc / NtFlushInstructionCache by a ROR13 hash of each export name
  (never by name string comparison, so the imported names never appear as plain text). It then
  does, by hand, what this project's MemoryLoadLibrary already does for a normal caller (copy
  headers/sections, resolve imports, apply relocations, call the entry point) - except here to
  load a SECOND, fully-formed copy of itself at a freshly VirtualAlloc'd address, elsewhere in the
  same (arbitrary, possibly remote) process.

  NOT the same problem MemoryModule.pas solves: MemoryLoadLibrary is called FROM a normal, fully
  running Delphi process that already has its own imports resolved - it never needs to self-locate
  kernel32 by hash, and it never runs before its own host process is fully initialized. This unit
  exists purely for reference / completeness, deliberately unattached to the rest of this project.

  CAVEAT - NOT VERIFIED SAFE FOR ACTUAL REMOTE INJECTION. The original C is written to avoid
  constructs its author knew would break position-independence (its own comment: no switch
  statement, specifically to avoid a compiler-generated jump table full of absolute addresses).
  This translation preserves that discipline where a direct equivalent exists (no dynamic strings,
  no exceptions, no RTL/CRT calls of its own), but the actual machine code Delphi emits for this
  function (jump tables for the `case` block below, any absolute-addressed helper call the
  compiler might still insert, string/RTTI table references) has NOT been verified byte-for-byte
  position-independent the way the C original's compiled output was presumably checked by its
  author. Treat this as an algorithmic reference translation, not a drop-in replacement for actual
  reflective-injection use, until/unless that is separately verified (e.g. by disassembling the
  compiled ReflectiveLoader function and confirming no unrelocated absolute addresses or jump
  tables survive in a real injection scenario). }

interface

uses
  Windows;

{$IFDEF FPC}
  {$mode delphi}
  {$IFDEF CPU64}
    {$DEFINE CPUX64}
  {$ENDIF}
{$ENDIF}

{$IFNDEF FPC}
{$IF CompilerVersion >= 23}
  {$LEGACYIFEND ON}
{$IFEND}
{$ENDIF}

{$WARN UNSAFE_TYPE OFF}
{$WARN UNSAFE_CODE OFF}
{$WARN UNSAFE_CAST OFF}
{$WARN COMBINING_SIGNED_UNSIGNED OFF}

// Mirrors ReflectiveLoader.c's exported DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(PVOID buffer):
// call with a pointer to this DLL's own raw image bytes (as originally mapped/written into memory,
// unrelocated, imports not yet resolved - see the caveat above for what that implies). Returns the
// newly, properly loaded copy's base address, or 0 on failure.
function ReflectiveLoader( buffer : Pointer ) : NativeUInt; stdcall;

implementation

{ ---- PE structure declarations, same guarded style / names as MemoryModule.pas (copied from
  there, since it already proved these compile correctly in this exact Delphi version, x86+x64) ---- }

type
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

{$IF NOT DECLARED( PIMAGE_NT_HEADERS32 )}
  PIMAGE_NT_HEADERS32 = ^IMAGE_NT_HEADERS;
{$IFEND}

// Own, uniquely-named 64-bit NT-header record - deliberately NOT reusing Windows.pas's own
// IMAGE_NT_HEADERS64/PIMAGE_NT_HEADERS64 names (whether or not it declares them, and under
// whichever of the two it does, varies enough across Delphi versions that a {$IF NOT DECLARED}
// guard on one half without the other is fragile - MemoryModule.pas hit exactly this. Owning the
// name outright sidesteps the ambiguity.)
type
  TRlImageOptionalHeader64 = record
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
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
    DataDirectory: packed array[ 0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1 ] of TImageDataDirectory;
  end;

  TRlImageNtHeaders64 = record
    Signature: DWORD;
    FileHeader: TImageFileHeader;
    OptionalHeader: TRlImageOptionalHeader64;
  end;
  PRlImageNtHeaders64 = ^TRlImageNtHeaders64;

// The module ReflectiveLoader loads is always the SAME bitness it was itself compiled for (a DLL's
// own raw bytes match its own build), so - like the C original's own #ifdef WIN_X64 branching -
// pick the correctly-shaped NT header type once, at compile time, and use it everywhere below.
{$IFDEF CPUX64}
  PIMAGE_NT_HEADERS_RL = PRlImageNtHeaders64;
{$ELSE}
  PIMAGE_NT_HEADERS_RL = PIMAGE_NT_HEADERS32;
{$ENDIF}

{$IF NOT DECLARED( IMAGE_BASE_RELOCATION )}
  {$ALIGN 4}
  IMAGE_BASE_RELOCATION = record
    VirtualAddress : Cardinal;
    SizeOfBlock    : Cardinal;
  end;
  {$ALIGN ON}
  PIMAGE_BASE_RELOCATION = ^IMAGE_BASE_RELOCATION;
{$IFEND}

{$IF NOT DECLARED( _IMAGE_IMPORT_DESCRIPTOR )}
  _IMAGE_IMPORT_DESCRIPTOR = record
    case Byte of
      0: ( Characteristics: Cardinal );
      1: ( OriginalFirstThunk: Cardinal;
           TimeDateStamp: Cardinal;
           ForwarderChain: Cardinal;
           Name: Cardinal;
           FirstThunk: Cardinal );
  end;
{$IFEND}

{$IF NOT DECLARED( PIMAGE_IMPORT_DESCRIPTOR )}
  PIMAGE_IMPORT_DESCRIPTOR = ^_IMAGE_IMPORT_DESCRIPTOR;
{$IFEND}

{$IF NOT DECLARED( IMAGE_IMPORT_DESCRIPTOR )}
  IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR;
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

const
{$IF NOT DECLARED( IMAGE_SIZEOF_BASE_RELOCATION )}
  IMAGE_SIZEOF_BASE_RELOCATION = 8;
{$IFEND}
  IMAGE_REL_BASED_ABSOLUTE = 0;
  IMAGE_REL_BASED_HIGH     = 1;
  IMAGE_REL_BASED_LOW      = 2;
  IMAGE_REL_BASED_HIGHLOW  = 3;
  IMAGE_REL_BASED_DIR64    = 10;

  IMAGE_ORDINAL_FLAG64 = UInt64( $8000000000000000 );
  IMAGE_ORDINAL_FLAG32 = LongWord( $80000000 );

  HASH_KEY = 13;

  KERNEL32DLL_HASH             = $6A4ABC5B;
  NTDLLDLL_HASH                = $3CFA685D;

  LOADLIBRARYA_HASH            = $EC0E4E8E;
  GETPROCADDRESS_HASH          = $7C0DFCAA;
  VIRTUALALLOC_HASH            = $91AFCA54;
  NTFLUSHINSTRUCTIONCACHE_HASH = $534C0AB8;

type
  TLoadLibraryA            = function( lpLibFileName : PAnsiChar ) : HMODULE; stdcall;
  TGetProcAddress          = function( hModule : HMODULE; lpProcName : PAnsiChar ) : Pointer; stdcall;
  TVirtualAlloc             = function( lpAddress : Pointer; dwSize : NativeUInt; flAllocationType, flProtect : DWORD ) : Pointer; stdcall;
  TNtFlushInstructionCache  = function( ProcessHandle : THandle; BaseAddress : Pointer; NumberOfBytesToFlush : ULONG ) : DWORD; stdcall;
  TDllMain                  = function( hInstDll : HINST; fdwReason : DWORD; lpReserved : Pointer ) : BOOL; stdcall;

  // Deliberately minimal - only the fields ReflectiveLoader itself touches, exactly like the
  // upstream C header. Every field is reached via a fixed, independently-known byte offset (see
  // RL_GetLdr below), not via this record's own layout, so - also like the upstream header - this
  // is a convenience view, not a byte-exact struct overlay of the real (much larger)
  // LDR_DATA_TABLE_ENTRY / PEB_LDR_DATA.
  PRlListEntry = ^TRlListEntry;
  TRlListEntry = record
    Flink, Blink : PRlListEntry;
  end;

  TRlUnicodeStr = record
    Length, MaximumLength : Word;
    pBuffer : PWideChar;
  end;

  PRlLdrDataTableEntry = ^TRlLdrDataTableEntry;
  TRlLdrDataTableEntry = record
    InMemoryOrderModuleList         : TRlListEntry;
    InInitializationOrderModuleList : TRlListEntry;
    DllBase                         : Pointer;
    EntryPoint                      : Pointer;
    SizeOfImage                     : Cardinal;
    FullDllName                     : TRlUnicodeStr;
    BaseDllName                     : TRlUnicodeStr;
    Flags                           : Cardinal;
    LoadCount                       : SmallInt;
    TlsIndex                        : SmallInt;
    HashTableEntry                  : TRlListEntry;
    TimeDateStamp                   : Cardinal;
  end;

  PRlPebLdrData = ^TRlPebLdrData;
  TRlPebLdrData = record
    dwLength, dwInitialized : Cardinal;
    lpSsHandle               : Pointer;
    InLoadOrderModuleList,
    InMemoryOrderModuleList,
    InInitializationOrderModuleList : TRlListEntry;
    lpEntryInProgress        : Pointer;
  end;

// ================================================================================================
// PEB access - own copy, same technique as MemoryModule.pas's MM_GetPEB (TEB is at GS:[$60] on
// x64 / FS:[$30] on x86; the PEB pointer sits there directly). Kept as a separate copy rather than
// referencing MemoryModule.pas, to keep this unit genuinely standalone.
// ================================================================================================
function RL_GetPEB : Pointer;
{$IFDEF CPUX64}
asm
  mov rax, gs:[$60]
end;
{$ELSE}
asm
  mov eax, fs:[$30]
end;
{$ENDIF}

function RL_GetLdr : PRlPebLdrData;
var
  peb : PByte;
begin
  Result := nil;
  peb := RL_GetPEB;
  if ( peb = nil ) then
    Exit;
  // PEB.Ldr: offset $18 on x64, $0C on x86 (same fixed, stable offset MM_GetLdr uses).
  Result := PRlPebLdrData( PPointer( peb + {$IFDEF CPUX64}$18{$ELSE}$0C{$ENDIF} )^ );
end;

// ================================================================================================
// ROR13 hashing - two variants, matching the upstream C exactly:
//  - RL_Hash: plain byte hash of a null-terminated ANSI string (used for export names).
//  - RL_HashUpper: byte hash of a fixed-length buffer, uppercasing ASCII lowercase bytes on the
//    fly (used for module names, which are UTF-16 UNICODE_STRING buffers hashed BYTE-for-byte
//    over their raw Length, not character-for-character - a faithful quirk of the original
//    technique, not a mistake: this hashes the raw bytes of the wide-char buffer, interleaved
//    zero-bytes included).
// ================================================================================================
function RL_Ror( d : Cardinal ) : Cardinal; inline;
begin
  Result := ( d shr HASH_KEY ) or ( d shl ( 32 - HASH_KEY ) );
end;

function RL_Hash( c : PAnsiChar ) : Cardinal;
var
  h : Cardinal;
begin
  h := 0;
  repeat
    h := RL_Ror( h );
    Inc( h, Byte( c^ ) );
    Inc( c );
  until ( c^ = #0 );
  Result := h;
end;

function RL_HashUpper( c : PByte; Len : Word ) : Cardinal;
var
  h : Cardinal;
begin
  h := 0;
  while ( Len > 0 ) do
    begin
    h := RL_Ror( h );
    if ( c^ >= Ord( 'a' ) ) then
      Inc( h, c^ - $20 )
    else
      Inc( h, c^ );
    Inc( c );
    Dec( Len );
    end;
  Result := h;
end;

// ================================================================================================
// ReflectiveLoader - line-for-line translation of ReflectiveLoader.c's ReflectiveLoader(). See the
// unit header comment for what "buffer" must point to and the position-independence caveat.
// ================================================================================================
function ReflectiveLoader( buffer : Pointer ) : NativeUInt; stdcall;
var
  pLoadLibraryA            : TLoadLibraryA;
  pGetProcAddress          : TGetProcAddress;
  pVirtualAlloc            : TVirtualAlloc;
  pNtFlushInstructionCache : TNtFlushInstructionCache;

  usCounter : Word;

  uiLibraryAddress : NativeUInt;
  uiBaseAddress    : NativeUInt;

  uiAddressArray : NativeUInt;
  uiNameArray    : NativeUInt;
  uiExportDir    : NativeUInt;
  uiNameOrdinals : NativeUInt;
  dwHashValue    : Cardinal;

  uiHeaderValue : NativeUInt;
  uiValueA, uiValueB, uiValueC, uiValueD, uiValueE : NativeUInt;

  ldrEntry   : PRlLdrDataTableEntry;
  expDir     : PIMAGE_EXPORT_DIRECTORY;
  impDesc    : PIMAGE_IMPORT_DESCRIPTOR;
  thunkRef   : PUINT_PTR;
  origThunk  : PUINT_PTR;
  thunkData  : PIMAGE_IMPORT_BY_NAME;
  baseReloc  : PIMAGE_BASE_RELOCATION;
  relInfo    : PWord;
  relType, relOffset : Integer;
  relocDelta : NativeUInt;
  ordinalFlag : UInt64;
begin
  Result := 0;
  pLoadLibraryA := nil;
  pGetProcAddress := nil;
  pVirtualAlloc := nil;
  pNtFlushInstructionCache := nil;
  {$IFDEF CPUX64}
  ordinalFlag := IMAGE_ORDINAL_FLAG64;
  {$ELSE}
  ordinalFlag := IMAGE_ORDINAL_FLAG32;
  {$ENDIF}

  // STEP 0: the initial location of this image in memory (the raw, as-yet-unloaded bytes).
  uiLibraryAddress := NativeUInt( buffer );

  // STEP 1: process the loaded modules' exports for the functions this loader needs, resolving
  // kernel32.dll and ntdll.dll purely by walking the PEB - no LoadLibrary/GetProcAddress calls of
  // our own are available yet, since our own import table (if we had a normal one) was never
  // resolved by the OS loader.
  ldrEntry := PRlLdrDataTableEntry( RL_GetLdr.InMemoryOrderModuleList.Flink );
  while ( Assigned( ldrEntry ) ) do
    begin
    if ( ldrEntry.BaseDllName.pBuffer = nil ) then
      Break;

    if ( RL_HashUpper( PByte( ldrEntry.BaseDllName.pBuffer ), ldrEntry.BaseDllName.Length ) = KERNEL32DLL_HASH ) then
      begin
      uiBaseAddress := NativeUInt( ldrEntry.DllBase );
      uiExportDir := uiBaseAddress + Cardinal( PIMAGE_DOS_HEADER( uiBaseAddress )._lfanew );
      uiExportDir := NativeUInt( @( PIMAGE_NT_HEADERS_RL( uiExportDir ).OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ] ) );
      uiExportDir := uiBaseAddress + PIMAGE_DATA_DIRECTORY( uiExportDir ).VirtualAddress;
      expDir := PIMAGE_EXPORT_DIRECTORY( uiExportDir );

      uiNameArray    := uiBaseAddress + expDir.AddressOfNames;
      uiNameOrdinals := uiBaseAddress + expDir.AddressOfNameOrdinals;

      usCounter := 3; // LoadLibraryA + GetProcAddress + VirtualAlloc
      while ( usCounter > 0 ) do
        begin
        dwHashValue := RL_Hash( PAnsiChar( uiBaseAddress + PCardinal( uiNameArray )^ ) );

        if ( ( dwHashValue = LOADLIBRARYA_HASH ) or ( dwHashValue = GETPROCADDRESS_HASH ) or ( dwHashValue = VIRTUALALLOC_HASH ) ) then
          begin
          uiAddressArray := uiBaseAddress + expDir.AddressOfFunctions;
          uiAddressArray := uiAddressArray + ( PWord( uiNameOrdinals )^ * SizeOf( Cardinal ) );

          if ( dwHashValue = LOADLIBRARYA_HASH ) then
            pLoadLibraryA := TLoadLibraryA( Pointer( uiBaseAddress + PCardinal( uiAddressArray )^ ) )
          else if ( dwHashValue = GETPROCADDRESS_HASH ) then
            pGetProcAddress := TGetProcAddress( Pointer( uiBaseAddress + PCardinal( uiAddressArray )^ ) )
          else if ( dwHashValue = VIRTUALALLOC_HASH ) then
            pVirtualAlloc := TVirtualAlloc( Pointer( uiBaseAddress + PCardinal( uiAddressArray )^ ) );

          Dec( usCounter );
          end;

        Inc( uiNameArray, SizeOf( Cardinal ) );
        Inc( uiNameOrdinals, SizeOf( Word ) );
        end;
      end
    else if ( RL_HashUpper( PByte( ldrEntry.BaseDllName.pBuffer ), ldrEntry.BaseDllName.Length ) = NTDLLDLL_HASH ) then
      begin
      uiBaseAddress := NativeUInt( ldrEntry.DllBase );
      uiExportDir := uiBaseAddress + Cardinal( PIMAGE_DOS_HEADER( uiBaseAddress )._lfanew );
      uiExportDir := NativeUInt( @( PIMAGE_NT_HEADERS_RL( uiExportDir ).OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ] ) );
      uiExportDir := uiBaseAddress + PIMAGE_DATA_DIRECTORY( uiExportDir ).VirtualAddress;
      expDir := PIMAGE_EXPORT_DIRECTORY( uiExportDir );

      uiNameArray    := uiBaseAddress + expDir.AddressOfNames;
      uiNameOrdinals := uiBaseAddress + expDir.AddressOfNameOrdinals;

      usCounter := 1; // NtFlushInstructionCache
      while ( usCounter > 0 ) do
        begin
        dwHashValue := RL_Hash( PAnsiChar( uiBaseAddress + PCardinal( uiNameArray )^ ) );

        if ( dwHashValue = NTFLUSHINSTRUCTIONCACHE_HASH ) then
          begin
          uiAddressArray := uiBaseAddress + expDir.AddressOfFunctions;
          uiAddressArray := uiAddressArray + ( PWord( uiNameOrdinals )^ * SizeOf( Cardinal ) );
          pNtFlushInstructionCache := TNtFlushInstructionCache( Pointer( uiBaseAddress + PCardinal( uiAddressArray )^ ) );
          Dec( usCounter );
          end;

        Inc( uiNameArray, SizeOf( Cardinal ) );
        Inc( uiNameOrdinals, SizeOf( Word ) );
        end;
      end;

    if ( Assigned( pLoadLibraryA ) and Assigned( pGetProcAddress ) and Assigned( pVirtualAlloc ) and Assigned( pNtFlushInstructionCache ) ) then
      Break;

    ldrEntry := PRlLdrDataTableEntry( ldrEntry.InMemoryOrderModuleList.Flink );
    end;

  if NOT ( Assigned( pLoadLibraryA ) and Assigned( pGetProcAddress ) and Assigned( pVirtualAlloc ) and Assigned( pNtFlushInstructionCache ) ) then
    Exit; // could not resolve the four functions needed - matches upstream's implicit failure mode

  // STEP 2: load our image into a new, permanent location in memory.
  uiHeaderValue := uiLibraryAddress + Cardinal( PIMAGE_DOS_HEADER( uiLibraryAddress )._lfanew );

  // Allocate all memory for the DLL up front; we relocate afterward so any address works. Marked
  // READ/WRITE/EXECUTE (matching upstream exactly) to avoid protection faults while patching
  // imports/relocations in place - a real loader would tighten this per-section afterward.
  uiBaseAddress := NativeUInt( pVirtualAlloc( nil, PIMAGE_NT_HEADERS_RL( uiHeaderValue ).OptionalHeader.SizeOfImage, MEM_RESERVE or MEM_COMMIT, PAGE_EXECUTE_READWRITE ) );
  if ( uiBaseAddress = 0 ) then
    Exit;

  // copy over the headers
  uiValueA := PIMAGE_NT_HEADERS_RL( uiHeaderValue ).OptionalHeader.SizeOfHeaders;
  uiValueB := uiLibraryAddress;
  uiValueC := uiBaseAddress;
  while ( uiValueA > 0 ) do
    begin
    PByte( uiValueC )^ := PByte( uiValueB )^;
    Inc( uiValueB );
    Inc( uiValueC );
    Dec( uiValueA );
    end;

  // STEP 3: load in all of our sections.
  uiValueA := NativeUInt( @PIMAGE_NT_HEADERS_RL( uiHeaderValue ).OptionalHeader ) + PIMAGE_NT_HEADERS_RL( uiHeaderValue ).FileHeader.SizeOfOptionalHeader;
  uiValueE := PIMAGE_NT_HEADERS_RL( uiHeaderValue ).FileHeader.NumberOfSections;
  while ( uiValueE > 0 ) do
    begin
    uiValueB := uiBaseAddress + PIMAGE_SECTION_HEADER( uiValueA ).VirtualAddress;
    uiValueC := uiLibraryAddress + PIMAGE_SECTION_HEADER( uiValueA ).PointerToRawData;
    uiValueD := PIMAGE_SECTION_HEADER( uiValueA ).SizeOfRawData;

    while ( uiValueD > 0 ) do
      begin
      PByte( uiValueB )^ := PByte( uiValueC )^;
      Inc( uiValueB );
      Inc( uiValueC );
      Dec( uiValueD );
      end;

    Inc( uiValueA, SizeOf( IMAGE_SECTION_HEADER ) );
    Dec( uiValueE );
    end;

  // STEP 4: process our image's import table (assumed present, matching upstream).
  uiValueB := NativeUInt( @PIMAGE_NT_HEADERS_RL( uiHeaderValue ).OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ] );
  uiValueC := uiBaseAddress + PIMAGE_DATA_DIRECTORY( uiValueB ).VirtualAddress;

  while ( PIMAGE_IMPORT_DESCRIPTOR( uiValueC ).Name <> 0 ) do
    begin
    impDesc := PIMAGE_IMPORT_DESCRIPTOR( uiValueC );

    uiLibraryAddress := NativeUInt( pLoadLibraryA( PAnsiChar( uiBaseAddress + impDesc.Name ) ) );

    uiValueD := uiBaseAddress + impDesc.OriginalFirstThunk; // VA of OriginalFirstThunk
    uiValueA := uiBaseAddress + impDesc.FirstThunk;          // VA of the IAT (FirstThunk)

    thunkRef := PUINT_PTR( uiValueA );
    origThunk := PUINT_PTR( uiValueD );

    while ( thunkRef^ <> 0 ) do
      begin
      if ( ( uiValueD <> 0 ) and ( ( origThunk^ and NativeUInt( ordinalFlag ) ) <> 0 ) ) then
        begin
        uiExportDir := uiLibraryAddress + Cardinal( PIMAGE_DOS_HEADER( uiLibraryAddress )._lfanew );
        uiExportDir := NativeUInt( @( PIMAGE_NT_HEADERS_RL( uiExportDir ).OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ] ) );
        uiExportDir := uiLibraryAddress + PIMAGE_DATA_DIRECTORY( uiExportDir ).VirtualAddress;
        expDir := PIMAGE_EXPORT_DIRECTORY( uiExportDir );

        uiAddressArray := uiLibraryAddress + expDir.AddressOfFunctions;
        uiAddressArray := uiAddressArray + ( ( ( origThunk^ and $FFFF ) - expDir.Base ) * SizeOf( Cardinal ) );

        thunkRef^ := uiLibraryAddress + PCardinal( uiAddressArray )^;
        end
      else
        begin
        uiValueB := uiBaseAddress + thunkRef^; // VA of the IMAGE_IMPORT_BY_NAME
        thunkData := PIMAGE_IMPORT_BY_NAME( uiValueB );
        thunkRef^ := NativeUInt( pGetProcAddress( HMODULE( uiLibraryAddress ), PAnsiChar( @thunkData.Name ) ) );
        end;

      Inc( NativeUInt( thunkRef ), SizeOf( NativeUInt ) );
      if ( uiValueD <> 0 ) then
        Inc( NativeUInt( origThunk ), SizeOf( NativeUInt ) );
      end;

    Inc( uiValueC, SizeOf( IMAGE_IMPORT_DESCRIPTOR ) );
    end;

  // STEP 5: process all of our image's relocations.
  relocDelta := uiBaseAddress - NativeUInt( PIMAGE_NT_HEADERS_RL( uiHeaderValue ).OptionalHeader.ImageBase );

  uiValueB := NativeUInt( @PIMAGE_NT_HEADERS_RL( uiHeaderValue ).OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ] );
  if ( PIMAGE_DATA_DIRECTORY( uiValueB ).Size <> 0 ) then
    begin
    uiValueC := uiBaseAddress + PIMAGE_DATA_DIRECTORY( uiValueB ).VirtualAddress;

    while ( PIMAGE_BASE_RELOCATION( uiValueC ).SizeOfBlock <> 0 ) do
      begin
      baseReloc := PIMAGE_BASE_RELOCATION( uiValueC );

      uiValueA := uiBaseAddress + baseReloc.VirtualAddress; // VA for this relocation block
      uiValueE := ( baseReloc.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION ) div SizeOf( Word );
      uiValueD := uiValueC + IMAGE_SIZEOF_BASE_RELOCATION;  // first entry in this block

      while ( uiValueE > 0 ) do
        begin
        relInfo := PWord( uiValueD );
        relType := relInfo^ shr 12;
        relOffset := relInfo^ and $0FFF;

        case relType of
          IMAGE_REL_BASED_DIR64 :
            Inc( PUInt64( uiValueA + NativeUInt( relOffset ) )^, relocDelta );
          IMAGE_REL_BASED_HIGHLOW :
            Inc( PCardinal( uiValueA + NativeUInt( relOffset ) )^, Cardinal( relocDelta ) );
          IMAGE_REL_BASED_HIGH :
            Inc( PWord( uiValueA + NativeUInt( relOffset ) )^, HIWORD( relocDelta ) );
          IMAGE_REL_BASED_LOW :
            Inc( PWord( uiValueA + NativeUInt( relOffset ) )^, LOWORD( relocDelta ) );
          // IMAGE_REL_BASED_ABSOLUTE and anything else: no-op, matching upstream.
        end;

        Inc( uiValueD, SizeOf( Word ) );
        Dec( uiValueE );
        end;

      uiValueC := uiValueC + baseReloc.SizeOfBlock;
      end;
    end;

  // STEP 6: call our image's entry point.
  uiValueA := uiBaseAddress + PIMAGE_NT_HEADERS_RL( uiHeaderValue ).OptionalHeader.AddressOfEntryPoint;

  // flush the instruction cache so stale code isn't used after our relocation patching.
  pNtFlushInstructionCache( THandle( -1 ), nil, 0 );

  TDllMain( Pointer( uiValueA ) )( HINST( uiBaseAddress ), DLL_PROCESS_ATTACH, Pointer( NativeInt( -1 ) ) );

  // STEP 8 (numbering matches upstream, which also has no STEP 7): return our base address.
  Result := uiBaseAddress;
end;

end.
