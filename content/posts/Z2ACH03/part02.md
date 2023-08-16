---
title: "Zero2Auto: Ch03-Practical Analysis Challenge (Part-II)"
date: 2023-08-14T15:46:46+05:30
description:  "Analysing Stage 02 of CH03 Challenge binary"
tags: [reverse engineering, zero2auto]
---

Yo Yo Yo!! Welcome back, in the part-II of analysing the challenge binary from Z2A: Ch03(Practical Analysis). 

> I encourage you to follow this writeup along with your analysis.

We gonna take a thorough look into second payload extracted from `.rsrc` section and injected into another process of stage01(`main_bin.exe`). So, let's get started from the `main` of this stage..

## Stage02: Extracted from `.rsrc` section of stage01

## INSIDE `main()`:
- {{< figure src="/assets/Z2ACH03Materials/Pseudocode_sub_main_stage02_1_half.png" title="Fig1. decompiled main() of stage02_1" >}}
- first gonna grab the file path of itself using `GetModuleFileNameA()`, to get the executable/file name using `sub_404A23` aka `strtok`(identified by flirt in cutter) using a loop
- with filename ie.  `main_bin.exe` (remember base payload spawned a child process of its own) in hand,  it will run another loop to get filename's length ie. `0xC`, then call to `sub_401600`(`CRC32` hashing), where filename being the first argument and second being the filename length, then compare it to a hard-coded hash `0xB925C42D` 
- if not equal then continue to call `sub_4010210`(`api_hash_resolving`) function which takes a module number among 3 ie.
- {{< figure src="/assets/Z2ACH03Materials/dllUsedInApiHashResolving_stage02.png" title="Fig2. dlls available to load from" >}}
- and a hard-coded hash, then return the API function name to immediately call it in the next line `call eax`, in this case it resolves the API hash `8436F795h` (`IsDebuggerPresent`) to check if this process is being debugged or not, if being debugged then exit the process
- Otherwise, go ahead and call another anti-debugging check function `sub_401000`

- ### INSIDE  `sub_401000()`:
	- this at first stores a hard-coded set of hash to `xmm0` from `xmmword_413CE0` variable, 

    - then move on to resolve some API function using `sub_4010210` and store them in registers to call'em later, those APIs are `0C1F3B876h`(`CreateToolhelp32Snapshot`), `8197004Ch`(`Process32FirstW`), `0BC6B67BFh`(`Process32NextW`)
    - next it calls `CreateToolhelp32Snapshot`(`call esi`) to take snapshot of running process, then if successfully retrieved the handle, then call `Process32FirstW` where the first arg is handle to snapshot and second arg being a `PROCESSENTRY32W` struct after setting `PROCESSENTRY32W->dwSize` to `0x22C`(`556`), 
	- then move on to call `Process32FirstW` to store the info about first process from snap in `PROCESSENTRY32W` struct, then lower the string of `PROCESSENTRY32W->szExeName` __(where every character is 2 bytes(aka `UTF-16`) means if string is `x32dbg.exe` then its hex will be `78 00 33 00 32 00 64 00 62 00 67 00 2e 00 65 00 78 00 65 00` ) like this, look at the dump for `x32dbg.exe` string__: 
	- {{< figure src="/assets/Z2ACH03Materials/anti_debugging_1_x64dbg_sub_401000_stage02.png" title="Fig3. decompiled sub_401000 of stage02" >}}
	- __contrary to previous `sub_401600` call where string chars are only 1byte  long were passed as argument means `x32dgb.exe`(`78 33 32 64 62 67 2e 65 78 65`) (pointing this out 'cause this makes difference in their hash calculated)__ , then calculate crc32hash to compare the hash the against hardcoded hash set of 4 stored in `xmm0` register earlier ie. (`7c6ffe70(processhacker.exe), 47742a22(wireshark.exe), d2f05b7d(x32dbg.exe), 659b537e(x64dbg.exe)` ), if not matched then call `Process32NextW` to goto the next process in snapshot, and repeat the comparision until any of'em matches, if none of'em matches then exit the function with return value of `0`: 
	- Otherwise, if any of running processes calculated hash matches to any of 4, then exit the function with return value of `1`

- if last function returned `0`(representing not being debugged), then move on to call `sub_401D50`, which gonna resolve some more API function and store them in for later use, with that done this calls another function `sub_401CA0`


- ### INSIDE `sub_401CA0()`:
	- {{< figure src="/assets/Z2ACH03Materials/Pseudocode_sub_401CA0_stage02.png" title="Fig4. decompiled sub_401CA0 of stage02" >}}
    
	- first set some memory of `0x40` bytes for struct `STARTUPINFOA`
	- then move on to decrypt some encrypted data stored in `xmmword_413C5C` and `xmmword_413C6C` ie. `7C6D1DBD1FEF1D5DDC6CCCBC5FEF891E` and `7CAD7CC86D1DDCAC1C4D1DEF0919FC` followed by a decryption loop containing shifting and xor to get string `C:\Windows\System32\svchost.exe` 
	- {{< figure src="/assets/Z2ACH03Materials/string_decryption_routine_svchostPath_cyberchef.png" title="Fig5. cyberchef recipe for decrypting svchost path string" >}}
	- then create the process `svchost.exe` using `CreateProcessA` (which was resolved in earlier function)  in suspended state and returns it `PROCESS_INFORMATION` struct 

- moving ahead in `main()` _(see image below)_, we see a call to `GetModuleHandleW` with `0` as argument means the module address of its own(stage02) which will be `0x400000`, 
- then allocate some memory space of size `0x18000`(`SizeOfImage` of stage02) using `VirtualAlloc` to copy the stage02 to allocated memory using `call sub_4037B0`
- now this allocates memory of size `0x18000` in suspended `svchost.exe` using `VirtualAllocEx`
- {{< figure src="/assets/Z2ACH03Materials/Pseudocode_sub_main_stage02_2_half.png" title="Fig6. decompiled main() of stage02_2" >}}

- then using some loop, gonna perform base relocation([Check me out for more on Base Relocation table](https://research32.blogspot.com/2015/01/base-relocation-table.html)) for the copied executable based on address returned from `VirtualAlloc` call, _**tldr**; this performs base relocation which needs to done when PE file is loaded to other address than image base address, in this case this is relocating the copied stage02 binary(present in `lpBuffer = lpMem`) to adjust the base relocation table with base address equal to address returned from `VirtualAlloc`_
- {{< figure src="/assets/Z2ACH03Materials/Pseudocode_sub_main_stage02_3_half.png" title="Fig7. decompiled main() of stage02_3" >}}
- after relocation, call to a `WriteProcessMemory` to write the relocated stage02 in the suspended `svchost.exe`,  
- then create  a remote thread in `svchost.exe` with `lpStartAddress` set to `sub_401DC0` relocated to new base address, with `dwCreationFlags` set to `0` means execute this routine immediately after creating the thread, 

> **TIP:** to break into `sub_401DCO:`
> - Now, in order to analyse this function in `x32dbg` , again attach the `svchost.exe` process before calling `CreateRemoteThread` 
> - follow the subroutine address(at offset `0x1DC0`) in disassembler  and place a breakpoint there  
> - then after calling `CreateRemoteThread` in parent process, jump onto the `svchost.exe` process and resume the debugger and you'll break on this function, if all goes good.

> _We've covered enough for a quick break, see you back in a bit_

---

## INSIDE `sub_401DC0()`:
> _Welcome back, i saw there you didn't had a break, nvm:) let's carry on.._

Now, let's examine this function, as this function is executed as a new thread within `svchost.exe` process:
- {{< figure src="/assets/Z2ACH03Materials/Pseudocode_sub_401DC0_stage02.png" title="Fig8. decompiled sub_401DC0 of stage02" >}}

- First, gonna resolve 4 API functions related to Internet, then gonna decrypt some encrypted data at `xmmword_41C7C` , `xmmword_413C8C`, `0xEA` using rotate left by `4`, then xor by `0xC5` to get this URL string `https://pastebin.com/raw/mLem9DGk`:
- {{< figure src="/assets/Z2ACH03Materials/string_decryption_routine_url1_cyberchef.png" title="Fig9. cyberchef recipe for decrypting url_1" >}}
- now pass the decrypted URL as only argument to `sub_401290(getDataFromUrl)` which  gonna reach out to URL and return the data received ie. another URL `https://i.ibb.co/KsfqHym/PNG-02-Copy.png` of an image
- again pass the data received(another URL) to `sub_4013A0()` as only argument,

## INSIDE `sub_4013A0()`:
- get data(`png` file) from URL passed to this function using `sub_401290(getDataFromUrl)`,

- then decrypt the data at `qword_413CA4`, `qword_413CAC` by rotating left by `4` then xor by `1F` to get string `\output.jpg` (keep endians in mind) and convert this string to `UTF-16`(wide character) by calling `MultiByteToWideChar`
- resolve 4 more API function using `api_hash_resolving_401210` ie. `GetTempPathW`, `CreateDirectoryW`, `CreateFileW`, `WriteFile`
- grab temporary directory path using `GetTempPathW`, to create a folder named `cruloader` using `CreateDirectoryW`, within this folder create a file named `output.jpg` and write the PNG file data received earlier using `WriteFile`,
- again decrypt data stored at `word_413CCC`, `qword_413CC4` ie. `8E FF EF BF 5F 6F FE 8E 9F` by rotating them left by `4` to xor them by `0x9A` to get string `redaolurc`
- Now using loop it finds the offset of data after string `redaolurc` (at offset `0x41107`) in PNG file ie. `0x41110`, then get the size of this data ie. `9384bytes(0x24A8)` followed by another loop to decrypt the data ie. xor by `0x61` which reveals another executable say stage03
- again call `sub_401D50`  to resolve some api function related to process creation and injection, then spawn another `svchost.exe` process using same call to `sub_401CA0` as earlier, then gonna call `sub_401750`

## INSIDE `sub_401750()`:
- this functions takes off by capturing the thread `Context` of newly spawned child `svchost.exe` process using `GetThreadContext()`, if function returns success then proceed otherwise return 1

- on success, read the image base address of suspended `svchost.exe` from `PEB->ImageBaseAddress` using `ReadProcessMemory()`
- on success, will compare the image base address of  stage03 and suspended `svchost.exe`, if equal then `NtUnmapViewOfSection()` is called to unmap view at child `svchost` image base address, otherwise if base addresses are not equal
- then move on to allocate memory of size `0x6000`(size of image of stage03) in child `svchos.exe`  using `VitualAllocEx` where `lpBaseAddress` set to `0x400000`(image base of stage03), if allocation not successfull, then retry memory allocation at any place (`lpBaseAddress = 0`), if this fails again then exit
- elsewsie, move on to replace `PEB->ImageBaseAddress` of child `svchost.exe` with allocated memory in `svchost.exe` using `WriteProcessMemory()`, 
- then modify the stage-03 payload by changing value of windows subsystem(`IMAGE_NT_HEADERS->OptionalHeader.Subsytem`) from `3(IMAGE_SUBSYSTEM_WINDOWS_CUI)` to `2(IMAGE_SUBSYSTEM_WINDOWS_GUI)`
- then check if previously allocated memory in child `svchost.exe`  is equal to image base address of stage03 payload, if not equal then relocation is done resp. to address allocated, otherwise if they're equal
- then make a jump to set the thread `Context->eax` (of child `svchost`) to the entry point(at offset `0x126F` of stage-03) then call `SetThreadContext` to set modified thread context in child svchost
- now using `WriteProcessMemory`, `VirtualProtectEx` gonna map the headers, sections with their protections of stage-03 payload to the allocated memory in child `svchost.exe`, like this:
- {{< figure src="/assets/Z2ACH03Materials/stage03_exec_mapping_inside_child_svchost_ProcessHacker.png" title="Fig10. stage03 mapped in svchost process memory" >}}
- then finally call `ResumeThread()` to continue execution of child `svchost.exe` from stage03's entry point

---

## Automations for this binary: 
## - API hash resolve
```python
# api_name_resolve.py
# Author: ME :D

import pefile
import zlib

def api_hash_resolve(dllToLoad, hashToResolve):
    pe = pefile.PE(f'C:\Windows\SysWOW64\{dllToLoad}')

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name is not None:
            if zlib.crc32(exp.name) == int(hashToResolve, 16):
                print(exp.name.decode())

def main():
    dllList = ["kernel32.dll", "ntdll.dll", "wininet.dll"]
    
    print(f"DLLs Available: \n0: {dllList[0]}\n1: {dllList[1]}\n2: {dllList[2]}")
    dllNumber = int(input("Choose DLL number: "))
    hashToResolve = input("Hash(hex) to Resolve: ")

    api_hash_resolve(dllList[dllNumber], hashToResolve)

if "__main__" == __name__:
    main()
```

## - Stage03 Extraction/Decryption from PNG file data:

```python
# stage03_extraction.py
# Author: ME :D

import urllib3

http = urllib3.PoolManager()
res = http.request('GET', 'https://i.ibb.co/KsfqHym/PNG-02-Copy.png')

xored_bytes_for_executable = bytearray()

for i in res.data[0x41110:]:
    xored_bytes_for_executable.append(i^0x61)

with open('stage03.bin', 'wb') as f:
    f.write(xored_bytes_for_executable)
```

---

## Conclusion:
Now that we know that this stage injects itself in a created `svchost` process to execute `sub_401DC0`, which reach out to internet to get an url to get a png file which contains an executable(stage03) file which then injected to created `svchost` process, in the next part we'll see what stage03 is capable of.

Next stage gonna blow your mind with its capability... See you there :)

