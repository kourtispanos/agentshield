; Inno Setup script for AgentShield.
; Build the exe first (see AgentShield.spec), then compile this with:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\installer.iss
; Result: installer_output\AgentShieldSetup.exe

#define MyAppName "AgentShield"
#define MyAppVersion "1.0"
#define MyAppExeName "AgentShield.exe"

[Setup]
AppId={{A6E2F3C1-9B74-4D2E-8F15-3C0A7B5E9D44}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=AgentShield
; Current user only - no admin rights needed, avoids Program Files permissions.
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\installer_output
OutputBaseFilename=AgentShieldSetup
SetupIconFile=..\frontend\assets\icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\dist\AgentShield\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: postinstall nowait skipifsilent
