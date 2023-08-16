---
title: "Zero2Auto: Ch03-Practical Analysis Challenge (Part-I)"
date: 2023-08-14T15:25:42+05:30
description:  "Analysing Base Stage01 of CH03 Challenge binary"
tags: [reverse engineering, zero2auto]
---

What is up guys, This post is walktrough of challenge binary(Chapter 03: Practical Analysis) from Zero2Auto course.
In this Part-I of this series we'll walkthrough the base binary(stage01) ie. `main_bin.exe`. So, let's get started...

# BASE PAYLOAD `main_bin.exe` (Stage01):

## INSIDE `main()`:
- Following is the modified/edited Pseudocode of `main()` based on IDA decompiler output:
```c
int __cdecl main(int argc, const char **argv, const char **envp) {
	decrypt_str_401300(str_kernel32dll);
	decrypt_str_401300(str_findResourceA);      
	hMod = LoadLibraryA(str_kernel32dll);
	FindResourceA = GetProcAddress(hMod, str_findResourceA);

	decrypt_str_401300(str_loadResource);
	hMod = LoadLibraryA(str_kernel32dll);
	LoadResource = GetProcAddress(hMod, str_loadResource);

	decrypt_str_401300(str_sizeOfResource);
	hMod = LoadLibraryA(str_kernel32dll);
	SizeOfResource = GetProcAddress(hMod, str_sizeOfResource);

	decrypt_str_401300(str_lockResource);
	hMod = LoadLibraryA(str_kernel32dll);
	LockResource = GetProcAddress(hMod, str_lockResource);

	// gonna load the desired resource from .rsrc section 
	hRsrc = FindResourceA(NULL, 101, RT_RCDATA);      
	hResLoad = LoadResource(NULL, hRsrc);
	dw_sizeOfRsrc = SizeOfResource(NULL, hRsrc);
	malloc_wrapper_4038F4(dw_sizeOfRsrc + 0x1C);
	lpRsrcLock = LockResource(hResLoad);

	// dwSize_of_next_payload = based on some calculation with lpRsrcLock+0x8

	decrypt_str_401300(str_virtualAlloc);
	hMod = LoadLibraryA(str_kernel32dll);
	VirtualAlloc = GetProcAddress(hMod, str_virtualAlloc);

	lpAlloc_mem_for_stg02 = VirtuaAlloc(0, dwSize_of_next_payload, MEM_COMMIT, PAGE_READWRITE);
	possible_memcpy_402DB0(lpAlloc_mem, lpRsrcLock+0x1C, dwSize_of_next_payload);

	possible_memset_4025B0(S_array, 0, 0x102); 
	//then rc4 decryption routine(with "key" being "lpRsrcLock+0xC" 
    // till next 15bytes in hex ie. "6b6b64355964504d32345642586d69") 
    // to get an PE file(next payload) at 'lpAlloc_mem_for_stg02' 

	// pass decrypted pe file to this funtions`
	sub_401000(lpAlloc_mem_for_stg02); 
	return 0;
}	
```

- This binary starts off by decrypting the needed module and win32API function name strings using `sub_401030` (which performs `ROT13` on encrypted string against `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./=`), to dynamically load them using `LoadLibraryA` followed by `GetProcAddress` 

- functions dynamically loaded are `FindResourceA`, `LoadResource`, `SizeOfResource`, `LockResource`, `VirtualAlloc` from `kernel32dll`
- moving on, we see it finds(`FindReosurceA`), loads(`LoadResource`), gets the size(`SizeOfResource`), lastly locks(`LockResource`) a resource from `.rsrc` section with `ID = 101(0x65)` of type `RT_RCDATA(0xA)` with size `0x1541C`
- then it calculates the size(based on `lpRsrcLock+0x8` ie. `0x2200`) for the data after offset `lpRsrcLock+0x1C` from resource ie. `0x1541C - 0x1C => 0x15400`, then allocates(`VirtualAlloc`) that much space to fill it with the buffer `lpRsrcLock+0x1C` using `sub_402DB0`
- moving on, we see the constant `256` a bunch of times along with loops containing enough arithmetic instruction, with a quick search it reveals that this is `RC4` decryption routine, not going deep into algorithm itself:
	- it's a 3 staged stream cipher algorithm consisting of 
	- `KSA(Key Scheduling Algorithm)`: which initializes a list of values from `0` to `256` which is then swapped with value based on calculation done with key
	- `PRGA(Pseudo-Random Generation Algorithm)`: generates and outputs the keystream using the scrambled list we had, and generates as many bytes needed up to `256`
	- `XOR` Operation: XORing each byte of ciphertext/plaintext with a byte of the keystream generated 
- in this case the key is the next `15` bytes from `lpRsrcLock+0xC` ie. `"6b6b64355964504d32345642586d69"` when the decryption routine finishes we're left with an executable in previously allocated memory, which is then passed as an only argument to `sub_401000`

---

## INSIDE `SUB_401000()`:
This Function gonna perform __PROCESS INJECTION__ using __THREAD CONTEXT HIJACKING__ in order to inject/execute the payload supplied as argument: 

- Following is the modified/edited Pseudocode of `sub_401000()` based on IDA decompiler output:

```c
int __thiscall sub_401000(_IMAGE_DOS_HEADER *stg02) {
	stg02_nt_Headers = stg02 + stg02->e_lfanew;
	ptr_stg02_nt_headers = stg02_nt_headers;

	// get current running executable's full path
	GetModuleFileNameA(NULL, lpFilename_self, 0x400); 
	
	// verify if stg02 payload is a legit PE file by verifying 
	if stg02_nt_headers->Signature != 0x4550
		return 1;

	possible_memset_4025B0(&lpStartupInfo, 0, 0x44);

	// now create the another process of itself(lpFilename) in suspended state(4) and store process information in 'lpProcessInfo' struct
	decryptStr_401300(str_kernel32dll);
	decryptStr_401300(str_CreatesProcessA);
	hMod = LoadLibraryA(str_kernel32dll);
	CreateProcessA = GetProcAddress(hMod, str_CreatesProcessA);
	if ( !CreateProcessA(lpFilename_self, 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &lpStartupInfo, &lpProcessInfo) )
	    return 1;

	decryptStr_401300(str_VirtualAlloc);
	hMod_1 = LoadLibraryA(str_kernel32dll);
	VirtualAlloc = GetProcAddress(hMod_1, str_VirtualAlloc);
	lpContext = VirtualAlloc(0, 4, MEM_COMMIT, PAGE_READWRITE);
	lpContext->ContextFlags = 0x10007;

	// get the thread context of thread inside suspended process
	decryptStr_401300(str_GetThreadContext);
	hMod_2 = LoadLibraryA(str_kernel32dll);
	GetThreadContext = GetProcAddress(hMod_2, str_GetThreadContext);
	if ( !GetThreadContext(lpProcessInfo.hThread, lpContext) )
		return 1;

	decryptStr_401300(str_ReadProcessMemory);
	hMod_3 = LoadLibraryA(str_kernel32dll);
	ReadProcessMemory = GetProcAddress(hMod_3, str_ReadProcessMemory);
	
	decryptStr_401300(str_WriteProcessMemory);
	hMod_4 = LoadLibraryA(str_kernel32dll);
	WriteProcessMemory = GetProcAddress(hMod_4, str_WriteProcessMemory);

	// copy the imageBaseAddress('lpContext->Ebx + 0x8' ie. PEB->ImageBaseAddress) to 'lpImageBaseOfSusProc'
	// lpContext->Ebx = at the time of suspended state this register holds the address of PEB
	ReadProcessMemory(lpProcessInfo->hProcess, lpContext->Ebx + 0x8, lpImageBaseOfSusProc, 0x4, NULL);

	// allocate memory in suspended process with base address 0x400000(stg02+0x134) of size 0x18000(stg02+0x150) with RWX(0x40) access
	decryptStr_401300(str_VirtualAllocEx);
	hMod_5 = LoadLibraryA(str_kernel32dll);
	VirtualAllocEx = GetProcAddress(hMod_5, str_VirtualAllocEx);
	lpMemInTargetProc = VirtualAllocEx(
						lpProcessInfo.hProcess,
						stg02_nt_headers->OptionalHeader.ImageBase,
						stg02_nt_headers->OptionalHeader.SizeOfImage,
						0x3000,
						PAGE_EXECUTE_READWRITE);

	// first gonna write the header of stg02 in memory allocated inside suspended process
	WriteProcessMemory(lpProcessInfo.hProcess, lpMemInTargetProc, stg02, stg02_nt_headers->OptionalHeader.SizeOfHeaders, 0);

	// if number of sections in stg02 is not 0
	if ( ptr_stg02_nt_headers->FileHeader.NumberOfSections ) {
		do {
		  // gonna run a loop to write all section of stg02 to the suspended process memory
		} while ( noOfSectionWritten < ptr_stg02_nt_headers->FileHeader.NumberOfSections );
	}

	// set the PEB->ImageBaseAddress(lpContext->Ebx+0x8) of supended process to imageBaseAddress of stg02 
	WriteProcessMemory(lpProcessInfo.hProcess, lpContext->Ebx + 0x8, stg02_nt_headers->OptionalHeader.ImageBase, 4, 0);
	
	decryptStr_401300(str_SetThreadContext);
	hMod_6 = LoadLibraryA(str_kernel32dll);
	SetThreadContext = GetProcAddress(hMod_6, str_SetThreadContext);
	
	decryptStr_401300(str_ResumeThread);
	hMod_7 = LoadLibraryA(str_kernel32dll);
	ResumeThread = GetProcAddress(hMod_7, str_ResumeThread);

	// now set: lpContext+Eax = original entry point of stg02 ie. 0x4022f3(main)
	lpContext->Eax = lpMemInTargetProc + ptr_stg02_nt_headers->OptionalHeader.AddressOfEntryPoint;
	// gonna set thread context of suspend, after modifying eax in it
	SetThreadContext(lpProcessInfo.hThread, lpContext);
	ResumeThread(lpProcessInfo.hThread);    // thne resume the suspended thread
	return 0;
}
```

- creates a child process of it's own in suspended state using `CreateProcessA()`

- then, get the thread `Context` of thread inside suspended process using `GetThreadContext()` in order to manipulate it later 
- allocate some memory in suspended process using `VirtualAllocEx` with base address `0x400000(stg02_nt_headers->OptionalHeader.ImageBase)`
- the using loop, this will write the payload section-by-section to the allocated memory using `WriteProcessMemory()`
- after injecting the payload in target process,  this set the thread context back using `SetThreadContext()` after modifying the `lpContext->Eax` to `0x4022F3` (ie. original entry point(`main`) of the stage02)
- then resume the suspended thread using `ResumeThread()`, which will immediately resume execution of injected payload from earlier set entry point

>  **TIP:** 
>  to break on the executing/injected payload in target process:
>  - attach the targeted process to `x32dbg`, then navigate to `Memory Map` tab , then `Follow in Dump` the memory(payload address of `0x400000` with size `0x18000`), you'll see an executable header(`4D5A..`), form here go to the entry point offset then `main`  in this case its `0x401EA0` then `Follow in Disassembler`, put a break point there
> - after resuming the thread from parent process, simply resume the debugger of child process and you'll jump to your intended breakpoint


## AUTOMATIONS FOR THIS BINARY:

## - String decryption performed by `sub_401300`:
```python
# decryptStr_401300.py
# Author: ME :D

# this decryption routine, kinda performs string decryption similar to ROT 13 but on given set of chararcters ie. 'all_chars'
def decrypt(enc_str):
	dec_str = ""
    all_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./="

    if(len(enc_str) > 0):
	    for i in range(len(enc_str)):
	        if enc_str[i] in all_chars:
	            index_of_chr = all_chars.index(enc_str[i])
                if (index_of_chr + 13) < len(all_chars):
	                dec_str += all_chars[index_of_chr + 13]
                else:
                    dec_str += all_chars[index_of_chr - len(all_chars) + 13]
return dec_str

if __name__ == "__main__":
	enc_str = input("String to decrypt: ")
    print("Decrypted Str: ", decrypt(enc_str))
```

## - Stage02 Extraction from `.rsrc` section and Decryption:
```python
import pefile
from arc4 import ARC4

def extract_rsrc(pe):
	for resrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
		for entry in resrc.directory.entries:
			# name of resource if present
			print("Resource Name:", entry.name)  
			# resource id of parent resource
			print("Resource ID(Parent):", entry.id) 
			# resource id of this resource
			print("Reosurce ID:", entry.directory.entries[0].id) 

			# get the size of this resource
			sizeOfRsrc = entry.directory.entries[0].data.struct.Size  
			print(f"Size of resource: {hex(sizeOfRsrc)}")

			# get the offset of this resource
			offsetToRsrc = entry.directory.entries[0].data.struct.OffsetToData
			print(f"Offset to resource: {hex(offsetToRsrc)}")

			# write the reosurce ot a variable to return
			rsrc = pe.get_memory_mapped_image()[offsetToRsrc:offsetToRsrc+sizeOfRsrc]

			return rsrc

def rc4_decrypt(key, data):
	cipher = ARC4(key)
	decrypted_data = cipher.decrypt(data)
	return decrypted_data

def main():
	pe = pefile.PE('main_bin.exe')
	# store the extracted resource
	extracted_resource = extract_rsrc(pe)  

	# RC4 decryption follows with key being 15bytes from 0xC, 
	# and rest of data is to be decrypted
	decrypted_resource = rc4_decrypt(extracted_resource[0xC:27], extracted_resource[0x1C:])
	executable = decrypted_resource

	# now write it to a new file
	with open("decrypted_Stage02.bin", "wb") as f:
		f.write(executable)

	print("[+]Done extracting..")

if "__main__" == __name__:
	main()
```

---

## Conclusion:
Now that we know, how the decryption of stage-02 is taking place using RC4 algorithm, also the 'key' for decryption and how the payload is injected and resumed to execute it and how put a breakpoint to it. Now in the part-II we'll focus on working of stage 02 

See you there :) 
