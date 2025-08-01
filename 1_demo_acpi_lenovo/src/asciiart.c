#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/LoadedImage.h>

static CONST CHAR16 *Art[] = {
L"It can also be argued that DNA is nothing more than a progra",
L"m designed to preserve ###*******##itself. Life has become m",
L"ore complex in the%*=:.             .:=*# overwhelming sea o",
L"f information. *=.                       .=#And life, when o",
L"rganized int%=.           .::--::.          .=#o species, re",
L"lies @upon%-           -*%@@@@@@@@%*-          =%@@@@@@ gene",
L"s to be i=           +%@@@@@@@@@@@@@@%=          +@@@@@ts me",
L"mory @@%:          .%@@@#==+%@@@#==+%@@#.         :@@@@syste",
L"m. So@%.   -+=     %@@@@    -@@@    :@@@%          .%@@, man",
L"is a %.   #@@@%   =@@@@@#=-=%@@@#=-+%@@@@-   .++++  .@@n ind",
L"ividu-   .#@@@#   +@@*=#@@@@@@@@@@@@%=+@@+   -@@@@:  =@al on",
L"ly b#  .#@@@@@@%+:=@@% #@@@@@@@@@@@@@ *@@:  .=@@@@*-  +ecaus",
L"e of=  .@@@@##@@@@@@@@#:*@@@@@@@@@@%:=@@#-*%@@@@@@@@* + his ",
L"inta-    -=:  .-*%@@@@@%==*######*=-*@@@@@@@%*=:+@@%- =ngibl",
L"e me-             :=#@@@@@#*++++*#%@@@@@%*=:      .   =mory.",
L".. a=                .-+#@@@@@@@@@@@%*=:              +nd me",
L"mory#                   .+**%@@@@#*=.                 - cann",
L"ot be:              .-*%@@@%+-+%@@@@@*=:             -@ defi",
L"ned, %     +**: .-*%@@@@%*=:    .=*%@@@@%*-. =+=.   .%@but i",
L"t def@#   *@@@@%@@@@%*=:            :+#@@@@@%@@@%   %@@ines ",
L"manki@@#. :#%@@@%*=.                   .-*%@@%#*: .%@@@nd. T",
L"he ad@@@%-  :@@@@:                        #@@@:  -@@@@@vent ",
L"of co@@@@@#:.%@@@-                        =@@#.:#@@@@@@mpute",
L"rs, and the *-::                            :-#subsequent ac",
L"cumulation of #=:                         :++incalculable da",
L"ta has given rise%*=:.               .-+*: to a new system o",
L"f memory and thought p%##*++===++*###arallel to your own. Hu",
L"manityhas underestimated the consequences of computerization",

  NULL
};

static CHAR16 Message[] = L"HELLO FROM THE PREBOOT!  SEE YOU SOON!";

EFI_STATUS EFIAPI
UefiMain (IN EFI_HANDLE ImageHandle,IN EFI_SYSTEM_TABLE  *SystemTable){

  EFI_STATUS                  Status;
  EFI_LOADED_IMAGE_PROTOCOL  *Self;
  EFI_DEVICE_PATH_PROTOCOL   *BakPath;
  EFI_HANDLE                  BakHandle = NULL;
  UINTN i, artLines;

  SystemTable->ConOut->SetAttribute(
    SystemTable->ConOut,
    EFI_GREEN | EFI_BACKGROUND_BLACK
  );

  for (i = 0; Art[i] != NULL; ++i) {
    Print(L"%s\n", Art[i]);
    gBS->Stall(300 * 1000);    // 300 ms delay
  }
  artLines = i;

  SystemTable->ConOut->SetAttribute(
    SystemTable->ConOut,
    EFI_RED | EFI_BACKGROUND_BLACK
  );
  Print(L"\n%s\n", Message);

  gBS->Stall(3 * 1000 * 1000);  // 3 s
  ///
  Status = gBS->OpenProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Self, ImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  Print (L"[shim] OpenProtocol(self) -> %r\n", Status);
  BakPath = FileDevicePath (Self->DeviceHandle, L"\\EFI\\Boot\\bootx64.dat");
  Status = gBS->LoadImage (FALSE, ImageHandle, BakPath, NULL, 0, &BakHandle);
  Print (L"[shim] LoadImage() -> %r\n", Status);  
  if (!EFI_ERROR (Status)) {
    Print (L"[shim] StartImage() ...\n");
    Status = gBS->StartImage (BakHandle, NULL, NULL);
    Print (L"[shim] StartImage returned -> %r\n", Status);
  }
  gBS->Stall(7 * 1000 * 1000);  // 3 s
  return EFI_SUCCESS;
}
