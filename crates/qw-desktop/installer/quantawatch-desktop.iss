; Inno Setup script for QuantaWatch Desktop.
;
; Produces a friendly setup.exe alternative to the MSI - useful for a "proper"
; interactive install or for building the installer yourself:
;
;   cargo build --release -p qw-desktop
;   iscc crates\qw-desktop\installer\quantawatch-desktop.iss
;
; CI overrides the version and output dir on the command line, e.g.:
;   iscc /DMyAppVersion=1.2.3 /Otarget\inno crates\qw-desktop\installer\quantawatch-desktop.iss

#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
; Path to the built exe, relative to THIS script's directory (installer/).
#ifndef SourceExe
  #define SourceExe "..\..\..\target\release\quantawatch-desktop.exe"
#endif

#define MyAppName "QuantaWatch Desktop"
#define MyAppPublisher "Dyber, Inc."
#define MyAppURL "https://github.com/dyber-pqc/QuantaWatch"
#define MyAppExeName "quantawatch-desktop.exe"

[Setup]
; Stable AppId (own GUID) so upgrades replace in place rather than stacking.
AppId={{7C4B9E2A-3F1D-4A6B-9E8C-2D5F6A7B8C90}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\QuantaWatch Desktop
DefaultGroupName=QuantaWatch
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
OutputBaseFilename=quantawatch-desktop-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
; Per-machine install (Program Files) needs admin.
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\QuantaWatch Desktop"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall QuantaWatch Desktop"; Filename: "{uninstallexe}"
Name: "{autodesktop}\QuantaWatch Desktop"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,QuantaWatch Desktop}"; Flags: nowait postinstall skipifsilent
