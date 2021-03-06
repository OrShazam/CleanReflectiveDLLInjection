.code 

ReflectiveLoader proc EXPORT lpParameter: LPVOID 
	; FULL OF ERRORS NEED TO FIX THIS 
	call getaddr
	func_base:
	
	module_base dq 0
	module_size dd 0 
	raw_size dd 0 
	loaded_module_base dq 0 
	modules_needed dd 2
	
	KERNEL32_HASH dd 6A4ABC5Bh
	NUMBER_OF_KERNEL32_FUNCTIONS dd 4
	
	kernel32_functions:
	
	LOAD_LIBRARY_HASH dd EC0E4E8Eh
	loadlibrary_addr dq 0
	
	GET_PROC_ADDRESS_HASH dd 7C0DFCAAh
	getprocaddr_addr dq 0
	
	VIRTUAL_ALLOC_HASH dd 91AFCA54h
	virtualalloc_addr dq 0
	
	VIRTUAL_FREE_HASH dd FFFFFFFFh 
	virtualfree_addr dq 0

	NTDLL_HASH dd 3CFA685Dh
	
	NUMBER_OF_NTDLL_FUNCTIONS dd 1 
		
	ntdll_functions:
	
	NT_FLUSH_INSTRUCTION_CACHE_HASH 534C0AB8h
	ntflushinstcache_addr dq 0
	
	
	getaddr:
	pop rbp 
	; search for image base - first entry in PEB wouldn't work
	; as this module is reflectively loaded 
	xor rcx,rcx 
	mov rbx, rbp 
	find_base_loop:
	dec rbx 
	cmp word [rbx], 5a4dh ; DOS_HEADER magic 
	jne find_base_loop
	mov cx, word [rbx+3ch] ;e_lfanew
	cmp cx, 1024 
	jg find_base_loop
	cmp dword [rbx+rcx], 00004550h ;NT_HEADERS magic 
	jne find_base_loop 
	mov [rbp + module_base - func_base], rbx 
	
	mov rax, gs:[60h] ;PEB 
	mov rax, [rax + 18h] ;Ldr 
	inc rax, 10
	mov r10, rax
	mov rax, [rax] ; host image 
	xor r8, r8
	xor r9, r9
	mov r8b, 20h
	not r8b 
	get_modules_loop:
	mov rax, [rax]
	cmp rax, r10 
	je failure 
	test rax, rax 
	jz failure 
	mov rcx, [rax+58h] ;BaseDllName.Length 
	mov rsi, [rax+60h] ;BaseDllName.Buffer 
	xor rdx, rdx 
	push rax 
	xor rax,rax
	calc_hash_loop:
	shl edx, 13
	lodsb 
	and al, r8b ; to uppercase 
	add edx, al 
	loop calc_hash_loop
	pop rax 
	cmp dword [rbp + KERNEL32_HASH - func_base], edx 
	je inc_and_jmp
	cmp dword [rbp + NTDLL_HASH - func_base], edx 
	je inc_and_jmp
	jmp get_modules_loop 
	
	inc_and_jmp:
	inc r9
	push r9 
	call get_functions_module 
	pop r9 
	cmp r9d, dword [rbp + modules_needed - func_base] 
	je get_modules_done
	jmp get_modules_loop 
	
	
	
	get_functions_module 
	; rax -> LDR_DATA_TABLE_ENTRY 
	; rdx -> module BaseDllName hash 
	mov rbx, [rax + 30h] ; DllBase 
	xor rcx,rcx 
	mov cx, [rbx + 3ch] ; e_lfanew 
	lea r9, [rbx + cx] 
	cmp dword [r9], 00004550h
	jne failure 
	mov ecx, dword [r9 + 88h] ;OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	lea r9, [rbx + ecx]
	xor r11,r11
	xor r12,r12
	xor r13,r13
	mov r11d, dword [r9 + 20h] ;IMAGE_EXPORT_DIRECTORY.AddressOfNames
	add r11, rbx
	mov r12d, dword [r9 + 24h] ;IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
	add r12, rbx 
	mov r13d, dword [r9 + 1ch] ;IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	add r13, rbx 
	mov r14d, dword [r9 + 18h] ;IMAGE_EXPORT_DIRECTORY.NumberOfNames 
	
	cmp dword [rbp + KERNEL32_HASH - func_base], edx 
	je get_functions_kernel32
	cmp dword [rbp + NTDLL_HASH - func_base], edx
	je get_functions_ntdll
	
	get_functions_kernel32:
	mov ecx, dword [rbp + NUMBER_OF_KERNEL32_FUNCTIONS - func_base]
	lea rdx, [ebp + kernel32_functions - func_base]
	jmp get_functions 
	
	get_functions_ntdll:
	mov ecx, dword [rbp + NUMBER_OF_NTDLL_FUNCTIONS - func_base]
	lea rdx, [rbp + ntdll_functions - func_base]
	jmp get_functions 
	
	get_functions:
	; rbx -> module base
	; rcx -> number of functions to find 
	; rdx -> base address of function data entries 
	; r11 -> names table 
	; r12 -> ordinals table 
	; r13 -> functions table 
	; r14 -> names table length 
	push rax 
	xor rax,rax 
	xor r8, r8 
	get_functions_loop:
	test r14,r14 
	je failure 
	xor rsi, rsi 
	mov esi, dword [r11]
	add rsi, rbx 
	xor r9, r9 
	calc_hash_loop:
	lodsb 
	test al, al 
	je end_calc_hash_loop
	shl r9d, 13
	add r9d, al 
	jmp calc_hash_loop
	
	end_calc_hash_loop:

	push rcx 
	lea rsi, [rdx] 
	lea rdi, [rdx + 4] 
	match_hash_loop:
	lodsd 
	cmp eax, r9d 
	jne continue_loop
	mov ax, word [r12]
	mov eax, dword [r13 + ax * 4] 
	add rax, rbx 
	mov [rdi], rax 
	inc r8 
	continue_loop:
	add rsi, 8 
	add rdi, 12 
	loop match_hash_loop
	pop rcx 
	add r11, 4
	add r12, 2
	dec r14 
	cmp r8, rcx 
	jne get_functions_loop 
	pop rax 
	ret 
	
	get_modules_done:
	mov rbx, [rbp + module_base - func_base] 
	xor rcx,rcx 
	mov cx, [rbx + 3ch] ; e_lfanew 
	lea rdx, [rbx + cx]
	xor rcx,rcx 
	push rdx 
	mov r8d, dword [rdx + 50h] ; OptionalHeader.SizeOfImage
	mov dword [rbp + module_size - func_base], r8d 
	xor rdx,rdx 
	add edx, r8d
	add rdx, cleanup_stub_end 
	sub rdx, cleanup_stub_start 
	xor r8,r8 
	mov r8d, 1000h ; MEM_COMMIT 
	or r8d, 2000h ; MEM_RESERVE
	xor r9,r9
	mov r9b, 40h ; PAGE_EXECUTE_READWRITE
	call [rbp + virtualalloc_addr - func_base]  
	test rax,rax 
	jz failure
	mov [rbp + loaded_module_base - func_base], rax 
	mov r8,rax 
	pop rdx
	mov ecx, dword [rdx + 54h] ; OptionalHeader.SizeOfHeaders 
	mov rsi, [rbp + module_base - func_base] 
	mov rdi, rax 
	rep movsb 
	xor rcx,rcx 
	mov rax, rdx 
	add rax, 4h
	add rax, 18h ; OptionalHeader
	mov cx, word [rdx + 14h] ; FileHeader.SizeOfOptionalHeader
	add rax, rcx 
	mov cx, word [rdx + 6h] ; FileHeader.NumberOfSections 
	map_sections_loop: 
	mov rsi, rbx 
	add esi, dword [rax + 16h] ; IMAGE_SECTION_HEADER.PointerToRawData
	mov rdi, r8 
	add edi, dword [rax + 0eh] ; IMAGE_SECTION_HEADER.VirtualAddress
	push rcx
	xor rcx,rcx 
	mov ecx, dword [rax + 12h] ; IMAGE_SECTION_HEADER.SizeOfRawData
	rep movsb 
	pop rcx 
	add rax, 42 ; sizeof(IMAGE_SECTION_HEADER)
	loop map_sections_loop
	sub rax, 42 
	add ecx, dword [rax + 16h] ; IMAGE_SECTION_HEADER.PointerToRawData
	add ecx, dword [rax + 12h] ; IMAGE_SECTION_HEADER.SizeOfRawData
	mov dword [rbp + raw_size - func_base], ecx 
	
	
	
	mov rbx, [rbp + loaded_module_base - func_base]
	; import table processing (already got addresses of LoadLibrary and GetProcAddress)
	mov r10, rbx 
	add r10d, dword [rdx + 90h]; IMAGE_DIRECTORY_ENTRY_IMPORT.VirtualAddress 
	sub r10, 20 
	resolve_imports_loop:
	add r10, 20 ; sizeof(IMAGE_DIRECTORY_ENTRY_EXPORT)
	mov r8, rbx 
	add r8d, dword [r10 + 0ch] ; IMAGE_DIRECTORY_ENTRY_IMPORT.Name 
	cmp r8, rbx 
	je process_relocations 
	mov rcx, r8 
	call [rbp + loadlibrary_addr - func_base] 
	mov r8, rax 
	mov r9, rbx
	add r9d, dword [r10 + 10h] ; IMAGE_DIRECTORY_ENTRY_EXPORT.FirstThunk
	sub r9, 8
	process_import_thunks:
	; r8 -> library base address 
	; r9 -> IMAGE_THUNK_DATA base 
	add r9, 8 ; sizeof(IMAGE_THUNK_DATA) 
	mov rax, [r9] 
	test rax,rax 
	jz resolve_imports_loop
	bt rax, 1 ; ordinal flag 
	jc resolve_by_ordinal
	add rax, rbx 
	add rax, 2 ; IMAGE_IMPORT_BY_NAME.Name
	push rdx 
	mov rcx, r8
	mov rdx, r9
	call [rbp + getprocaddr_addr - func_base] 
	pop rdx 
	mov [r9], rax 
	jmp process_import_thunks
	resolve_by_ordinal:
	push rdx 
	xor rcx,rcx 
	mov cx, word [r8 + 3ch] ; e_lfanew
	lea rdx, [r8 + rcx] 
	mov ecx, dword [rdx + 88h] ; DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	lea rdx, [r8 + rcx] 
	mov rcx, r8
	add ecx, dword [rdx + 1ch] ;IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	mov rsi, r8 
	add esi, dword [rcx + rax * 4] 
	mov [r9], rsi 
	pop rdx 
	jmp process_import_thunks
	
	process_relocations:
	;todo - relocations processing
	
	copy_and_call_stub: 
	lea rsi, [rbp + cleanup_stub_start - func_base] 
	mov rdi, rbx 
	xor rcx, rcx 
	mov ecx, dword [rbp + module_size - func_base]
	add rdi, rcx  
	push rdi 
	rep movsb 
	not rcx ; rcx = -1 
	xor rdx rdx 
	xor r8, r8 
	call [rbp + ntflushinstcache_addr - func_base] 
	pop r10 
	mov ecx, dword [rbp + raw_size - func_base]
	mov rax, [rbp + loaded_module_base - func_base] 
	mov r8, rax
	add eax, dword [rdx + 28h] ; OptionalHeader.AddressOfEntryPoint
	mov rdx, rbx 
	mov rbx, [rbp + virtualfree_addr - func_base]  
	mov r9, lpParameter
	call r10 
	
	failure:
	ret 
	
	cleanup_stub_start:
	; rax -> address of entry point 
	; rbx -> address of VirtualFree 
	; rcx -> size of raw file 
	; rdx -> base address of raw file 
	; r8 -> base address of loaded file
	; r9 -> lpParameter 
	push rax 
	xor rax,rax
	mov rdi, rdx 
	rep stosb 
	mov rcx,rdx 
	xor rdx,rdx 
	push r8 
	xor r8, r8 
	mov r8d, 0x00008000 ; MEM_RELEASE 
	call rbx 
	pop r8 
	pop rax
	mov rcx, r8 ;hinstDll
	inc rdx ; DLL_PROCESS_ATTACH 
	mov r8, r9 ;lpParameter 
	call rax ;DllMain 
	ret 
	cleanup_stub_end:
	nop

ReflectiveLoader endp 
end
