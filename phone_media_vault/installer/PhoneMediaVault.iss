; Inno Setup 6 script for Phone Media Vault (خزنة الوسائط).
; Build the PyInstaller folder first (installer\build.ps1 does both steps).
#define AppName "Phone Media Vault"
#define AppVersion GetEnv("PMV_VERSION")
#if AppVersion == ""
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{6C3E2F7A-9D4B-4E7B-9A51-0D3C1F2B8E61}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Phone Media Vault
DefaultDirName={autopf}\PhoneMediaVault
DefaultGroupName={#AppName}
OutputDir=..\dist\installer
OutputBaseFilename=PhoneMediaVault-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern
UninstallDisplayIcon={app}\PhoneMediaVault.exe
#ifexist "assets\app.ico"
SetupIconFile=assets\app.ico
#endif

[Languages]
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\PhoneMediaVault\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\PhoneMediaVault.exe"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\PhoneMediaVault.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\PhoneMediaVault.exe"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

; Note: user data (signing key, settings, history in %LOCALAPPDATA%\PhoneMediaVault)
; is intentionally NOT removed on uninstall, so existing backups stay verifiable.
