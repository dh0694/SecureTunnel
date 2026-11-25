; SecureTunnel Windows installer (built on Linux with makensis).
;
;   SecureTunnel-Setup.exe                          interactive install
;   SecureTunnel-Setup.exe /S /SERVER=vpn.example.com
;   SecureTunnel-Setup.exe /S /SERVER=203.0.113.10 /PIN=<sha256>
;   SecureTunnel-Setup.exe /S /SERVER=vpn.example.com /BACKUP=vpn2.example.com,198.51.100.7
;
; /SERVER  control server name or IP (IP alone means port 8443; name alone means 443)
; /PIN     optional SHA-256 of the server's public key (otherwise saved on first connect)
; /BACKUP  optional backup addresses, comma separated, used when /SERVER can't be reached
; /S       silent (for Intune / scripted installs)

Unicode true
SetCompressor /SOLID lzma
ManifestDPIAware true

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!ifndef VERSION
  !define VERSION "0.1.0"
!endif

Name "SecureTunnel"
OutFile "SecureTunnel-Setup.exe"
InstallDir "$PROGRAMFILES64\SecureTunnel"
RequestExecutionLevel admin
BrandingText "SecureTunnel ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "SecureTunnel"
VIAddVersionKey "FileDescription" "SecureTunnel installer"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "SecureTunnel"

!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open SecureTunnel"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Var Server
Var Pin
Var Backup
Var Args

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "SecureTunnel needs 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/SERVER=" $Server
  ClearErrors
  ${GetOptions} $R0 "/PIN=" $Pin
  ClearErrors
  ${GetOptions} $R0 "/BACKUP=" $Backup
  ClearErrors
FunctionEnd

Function LaunchApp
  ; Start the tray app as the signed-in user, not elevated.
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\securetunnel.exe"'
FunctionEnd

Section "SecureTunnel" SecMain
  SetShellVarContext all
  SetOutPath "$INSTDIR"

  ; Upgrade: stop the old service and tray app so files can be replaced.
  ; --keep-settings keeps the server address and certificate pin.
  ; The saved VPN session is set aside first: older versions delete it while
  ; uninstalling, and keeping it lets the new version reconnect by itself
  ; (no new sign-in) after an update.
  ${If} ${FileExists} "$INSTDIR\securetunnel.exe"
    ${If} ${FileExists} "$APPDATA\SecureTunnel\session.dat"
      Delete "$APPDATA\SecureTunnel\session.dat.upgrade"
      CopyFiles /SILENT "$APPDATA\SecureTunnel\session.dat" "$APPDATA\SecureTunnel\session.dat.upgrade"
    ${EndIf}
    DetailPrint "Stopping the existing SecureTunnel..."
    nsExec::ExecToLog '"$INSTDIR\securetunnel.exe" uninstall --keep-settings'
    Pop $0
    ${If} ${FileExists} "$APPDATA\SecureTunnel\session.dat.upgrade"
      Delete "$APPDATA\SecureTunnel\session.dat"
      Rename "$APPDATA\SecureTunnel\session.dat.upgrade" "$APPDATA\SecureTunnel\session.dat"
    ${EndIf}
  ${EndIf}
  nsExec::Exec 'taskkill /F /IM securetunnel.exe'
  Pop $0
  Sleep 500

  File "securetunnel.exe"
  File "wireguard.dll"
  File "icon.ico"

  StrCpy $Args "install"
  ${If} $Server != ""
    StrCpy $Args '$Args --server "$Server"'
  ${EndIf}
  ${If} $Pin != ""
    StrCpy $Args '$Args --pin "$Pin"'
  ${EndIf}
  ${If} $Backup != ""
    StrCpy $Args '$Args --backup "$Backup"'
  ${EndIf}
  DetailPrint "Setting up the SecureTunnel service..."
  nsExec::ExecToLog '"$INSTDIR\securetunnel.exe" $Args'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "SecureTunnel couldn't set up its service (error $0).$\r$\nSee C:\ProgramData\SecureTunnel\install.log." /SD IDOK
    Abort
  ${EndIf}

  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortCut "$SMPROGRAMS\SecureTunnel.lnk" "$INSTDIR\securetunnel.exe" "" "$INSTDIR\icon.ico"

  !define UNINST "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecureTunnel"
  WriteRegStr HKLM "${UNINST}" "DisplayName" "SecureTunnel"
  WriteRegStr HKLM "${UNINST}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST}" "Publisher" "SecureTunnel"
  WriteRegStr HKLM "${UNINST}" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKLM "${UNINST}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST}" "EstimatedSize" "$0"
SectionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

Section "Uninstall"
  SetShellVarContext all
  DetailPrint "Removing the SecureTunnel service..."
  nsExec::ExecToLog '"$INSTDIR\securetunnel.exe" uninstall'
  Pop $0
  nsExec::Exec 'taskkill /F /IM securetunnel.exe'
  Pop $0
  Sleep 500
  Delete "$INSTDIR\securetunnel.exe"
  Delete "$INSTDIR\wireguard.dll"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\SecureTunnel.lnk"
  RMDir /r "$COMMONAPPDATA\SecureTunnel"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SecureTunnel"
SectionEnd
