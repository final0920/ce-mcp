use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{process, util, ToolResponse};
use crate::domain::fingerprint::ModuleFingerprint;
use crate::runtime;

const METHODS: &[&str] = &["get_module_fingerprint"];
const PE_HEADER_READ_SIZE: usize = 0x1000;
const MAX_PE_HEADER_READ_SIZE: usize = 0x10000;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

pub fn dispatch(method: &str, params_json: &str) -> Option<ToolResponse> {
    let response = match method {
        "get_module_fingerprint" => get_module_fingerprint(params_json),
        _ => return None,
    };

    Some(response)
}

#[allow(dead_code)]
pub fn supported_methods() -> &'static [&'static str] {
    METHODS
}

fn get_module_fingerprint(params_json: &str) -> ToolResponse {
    let Some(app) = runtime::app_state() else {
        return error_response("runtime not initialized".to_owned());
    };

    let params = match util::parse_params(params_json) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let module_name = match params
        .get("module_name")
        .or_else(|| params.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
    {
        Some(name) if !name.is_empty() => name,
        _ => return error_response("missing module_name".to_owned()),
    };

    let modules = process::current_modules();
    let Some(module) = process::find_module_by_name(module_name, &modules) else {
        return error_response(format!("module not found: {}", module_name));
    };

    let header = app
        .opened_process_handle()
        .and_then(|handle| read_module_pe_metadata(handle, module.base_address).ok());

    let section_hashes = app
        .opened_process_handle()
        .and_then(|handle| {
            header
                .as_ref()
                .map(|metadata| compute_section_hashes(handle, module.base_address, metadata))
        })
        .unwrap_or_default();
    let import_hash = app.opened_process_handle().and_then(|handle| {
        header
            .as_ref()
            .and_then(|metadata| compute_import_hash(handle, module.base_address, metadata))
    });

    let fingerprint = ModuleFingerprint {
        build_version: params
            .get("build_version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        module_name: module.name.clone(),
        pe_timestamp: header.as_ref().and_then(|value| value.pe_timestamp),
        image_size: header
            .as_ref()
            .and_then(|value| value.image_size)
            .or(Some(module.size as u64)),
        entry_point_rva: header
            .as_ref()
            .and_then(|value| value.entry_point_rva)
            .map(util::format_rva),
        image_base: header
            .as_ref()
            .and_then(|value| value.image_base)
            .or(Some(module.base_address as u64))
            .map(util::format_u64_hex),
        machine: header
            .as_ref()
            .and_then(|value| value.machine)
            .map(machine_to_string)
            .or_else(|| Some("x64".to_owned())),
        section_hashes,
        import_hash,
    };

    ToolResponse {
        success: true,
        body_json: json!({
            "success": true,
            "fingerprint": fingerprint,
            "path": module.path,
            "resolved_module_name": module.name,
            "header_reader": if header.is_some() { "remote_pe_header" } else { "module_enumeration_fallback" },
        })
        .to_string(),
    }
}

#[derive(Debug, Clone)]
struct PeMetadata {
    pe_timestamp: Option<u32>,
    image_size: Option<u64>,
    entry_point_rva: Option<usize>,
    image_base: Option<u64>,
    machine: Option<u16>,
    optional_magic: Option<u16>,
    import_directory_rva: Option<u32>,
    import_directory_size: Option<u32>,
    sections: Vec<SectionHeader>,
}

#[derive(Debug, Clone)]
struct SectionHeader {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    size_of_raw_data: u32,
}

fn read_module_pe_metadata(
    handle: *mut core::ffi::c_void,
    module_base: usize,
) -> Result<PeMetadata, String> {
    let mut bytes = runtime::read_process_memory(handle, module_base, PE_HEADER_READ_SIZE)?;
    let e_lfanew = parse_e_lfanew(&bytes)?;
    let minimum = e_lfanew.saturating_add(0x200).min(MAX_PE_HEADER_READ_SIZE);
    if minimum > bytes.len() {
        bytes = runtime::read_process_memory(handle, module_base, minimum)?;
    }

    let required = required_pe_size(&bytes)?.min(MAX_PE_HEADER_READ_SIZE);
    if required > bytes.len() {
        bytes = runtime::read_process_memory(handle, module_base, required)?;
    }

    parse_pe_metadata(&bytes)
}

fn parse_e_lfanew(bytes: &[u8]) -> Result<usize, String> {
    if bytes.len() < 0x40 {
        return Err("module header too small for DOS header".to_owned());
    }
    if bytes.get(0..2) != Some(b"MZ") {
        return Err("module does not start with MZ header".to_owned());
    }

    let e_lfanew = u32::from_le_bytes(
        bytes[0x3C..0x40]
            .try_into()
            .map_err(|_| "failed to read e_lfanew".to_owned())?,
    ) as usize;
    Ok(e_lfanew)
}

fn required_pe_size(bytes: &[u8]) -> Result<usize, String> {
    let e_lfanew = parse_e_lfanew(bytes)?;
    let file_header_offset = e_lfanew.saturating_add(4);
    ensure_range(bytes, file_header_offset, 20, "COFF header")?;
    let size_of_optional_header = read_u16(bytes, file_header_offset + 16)? as usize;
    let number_of_sections = read_u16(bytes, file_header_offset + 2)? as usize;
    Ok(file_header_offset
        .saturating_add(20)
        .saturating_add(size_of_optional_header)
        .saturating_add(number_of_sections.saturating_mul(40)))
}

fn parse_pe_metadata(bytes: &[u8]) -> Result<PeMetadata, String> {
    let e_lfanew = parse_e_lfanew(bytes)?;
    let pe_header_offset = e_lfanew;
    let file_header_offset = pe_header_offset.saturating_add(4);
    let optional_header_offset = file_header_offset.saturating_add(20);

    ensure_range(bytes, pe_header_offset, 4, "PE signature")?;
    if bytes.get(pe_header_offset..pe_header_offset + 4) != Some(b"PE\0\0") {
        return Err("invalid PE signature".to_owned());
    }

    ensure_range(bytes, file_header_offset, 20, "COFF header")?;
    let machine = read_u16(bytes, file_header_offset)?;
    let pe_timestamp = Some(read_u32(bytes, file_header_offset + 4)?);
    let number_of_sections = read_u16(bytes, file_header_offset + 2)? as usize;
    let size_of_optional_header = read_u16(bytes, file_header_offset + 16)? as usize;
    if size_of_optional_header == 0 {
        return Ok(PeMetadata {
            pe_timestamp,
            image_size: None,
            entry_point_rva: None,
            image_base: None,
            machine: Some(machine),
            optional_magic: None,
            import_directory_rva: None,
            import_directory_size: None,
            sections: Vec::new(),
        });
    }

    ensure_range(
        bytes,
        optional_header_offset,
        size_of_optional_header,
        "optional header",
    )?;
    let magic = read_u16(bytes, optional_header_offset)?;
    let entry_point_rva = Some(read_u32(bytes, optional_header_offset + 16)? as usize);
    let image_base = match magic {
        0x20B => Some(read_u64(bytes, optional_header_offset + 24)?),
        0x10B => Some(read_u32(bytes, optional_header_offset + 28)? as u64),
        _ => None,
    };
    let image_size = Some(read_u32(bytes, optional_header_offset + 56)? as u64);

    let data_directory_offset = match magic {
        0x20B => optional_header_offset + 112,
        0x10B => optional_header_offset + 96,
        _ => optional_header_offset + size_of_optional_header,
    };
    let (import_directory_rva, import_directory_size) =
        if data_directory_offset + 8 * 2 <= bytes.len() {
            let entry_offset = data_directory_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
            (
                Some(read_u32(bytes, entry_offset)?),
                Some(read_u32(bytes, entry_offset + 4)?),
            )
        } else {
            (None, None)
        };

    let section_table_offset = optional_header_offset + size_of_optional_header;
    let mut sections = Vec::new();
    for index in 0..number_of_sections {
        let offset = section_table_offset + index * 40;
        ensure_range(bytes, offset, 40, "section header")?;
        let raw_name = &bytes[offset..offset + 8];
        let name_end = raw_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..name_end]).to_string();
        sections.push(SectionHeader {
            name,
            virtual_size: read_u32(bytes, offset + 8)?,
            virtual_address: read_u32(bytes, offset + 12)?,
            size_of_raw_data: read_u32(bytes, offset + 16)?,
        });
    }

    Ok(PeMetadata {
        pe_timestamp,
        image_size,
        entry_point_rva,
        image_base,
        machine: Some(machine),
        optional_magic: Some(magic),
        import_directory_rva,
        import_directory_size,
        sections,
    })
}

fn compute_section_hashes(
    handle: *mut core::ffi::c_void,
    module_base: usize,
    metadata: &PeMetadata,
) -> BTreeMap<String, String> {
    let mut section_hashes = BTreeMap::new();

    for section in &metadata.sections {
        let size = usize::try_from(section.virtual_size.max(section.size_of_raw_data)).unwrap_or(0);
        if size == 0 {
            continue;
        }
        let address = module_base.saturating_add(section.virtual_address as usize);
        let Ok(bytes) = runtime::read_process_memory(handle, address, size) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        section_hashes.insert(section.name.clone(), format!("{:x}", md5::compute(bytes)));
    }

    section_hashes
}

fn compute_import_hash(
    handle: *mut core::ffi::c_void,
    module_base: usize,
    metadata: &PeMetadata,
) -> Option<String> {
    let import_rva = metadata.import_directory_rva?;
    let import_size = metadata.import_directory_size?;
    if import_rva == 0 || import_size == 0 {
        return None;
    }

    let thunk_size = match metadata.optional_magic {
        Some(0x20B) => 8usize,
        Some(0x10B) => 4usize,
        _ => 8usize,
    };
    let mut imports = Vec::new();
    let mut descriptor_address = module_base.saturating_add(import_rva as usize);
    let max_descriptors = (import_size as usize / 20).max(1).min(4096);

    for _ in 0..max_descriptors {
        let bytes = runtime::read_process_memory(handle, descriptor_address, 20).ok()?;
        if bytes.len() < 20 {
            break;
        }
        let original_first_thunk = read_u32(&bytes, 0).ok()?;
        let name_rva = read_u32(&bytes, 12).ok()?;
        let first_thunk = read_u32(&bytes, 16).ok()?;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll_name = read_c_string(handle, module_base.saturating_add(name_rva as usize), 256)?
            .to_ascii_lowercase();
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let mut thunk_address = module_base.saturating_add(thunk_rva as usize);

        for _ in 0..4096 {
            let entry = if thunk_size == 8 {
                let data = runtime::read_process_memory(handle, thunk_address, 8).ok()?;
                if data.len() < 8 {
                    break;
                }
                u64::from_le_bytes(data[0..8].try_into().ok()?)
            } else {
                let data = runtime::read_process_memory(handle, thunk_address, 4).ok()?;
                if data.len() < 4 {
                    break;
                }
                u32::from_le_bytes(data[0..4].try_into().ok()?) as u64
            };
            if entry == 0 {
                break;
            }

            let ordinal_flag = if thunk_size == 8 {
                0x8000_0000_0000_0000u64
            } else {
                0x8000_0000u64
            };
            if entry & ordinal_flag != 0 {
                imports.push(format!("{}.#{}", dll_name, entry & 0xFFFF));
            } else {
                let import_by_name = module_base.saturating_add(entry as usize);
                let function_name = read_c_string(handle, import_by_name.saturating_add(2), 512)?
                    .to_ascii_lowercase();
                imports.push(format!("{}.{}", dll_name, function_name));
            }

            thunk_address = thunk_address.saturating_add(thunk_size);
        }

        descriptor_address = descriptor_address.saturating_add(20);
    }

    if imports.is_empty() {
        return None;
    }

    Some(format!("{:x}", md5::compute(imports.join(","))))
}

fn read_c_string(handle: *mut core::ffi::c_void, address: usize, max_len: usize) -> Option<String> {
    let bytes = runtime::read_process_memory(handle, address, max_len).ok()?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).to_string())
}

fn ensure_range(bytes: &[u8], offset: usize, len: usize, label: &str) -> Result<(), String> {
    if offset
        .checked_add(len)
        .is_some_and(|end| end <= bytes.len())
    {
        return Ok(());
    }

    Err(format!("module header too small for {}", label))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    ensure_range(bytes, offset, 2, "u16")?;
    Ok(u16::from_le_bytes(
        bytes[offset..offset + 2].try_into().unwrap(),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    ensure_range(bytes, offset, 4, "u32")?;
    Ok(u32::from_le_bytes(
        bytes[offset..offset + 4].try_into().unwrap(),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    ensure_range(bytes, offset, 8, "u64")?;
    Ok(u64::from_le_bytes(
        bytes[offset..offset + 8].try_into().unwrap(),
    ))
}

fn machine_to_string(machine: u16) -> String {
    match machine {
        0x014C => "x86",
        0x8664 => "x64",
        0xAA64 => "arm64",
        0x01C0 => "arm",
        other => return format!("0x{:04X}", other),
    }
    .to_owned()
}

fn error_response(message: String) -> ToolResponse {
    ToolResponse {
        success: false,
        body_json: message,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_pe_metadata;

    #[test]
    fn parses_pe32_plus_header() {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&(1u16).to_le_bytes());
        bytes[0x88..0x8C].copy_from_slice(&(0x12345678u32).to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&(0xF0u16).to_le_bytes());
        bytes[0x98..0x9A].copy_from_slice(&(0x20Bu16).to_le_bytes());
        bytes[0xA8..0xAC].copy_from_slice(&(0x2000u32).to_le_bytes());
        bytes[0xB0..0xB8].copy_from_slice(&(0x140000000u64).to_le_bytes());
        bytes[0xD0..0xD4].copy_from_slice(&(0x500000u32).to_le_bytes());
        bytes[0x108..0x10C].copy_from_slice(&(0x3000u32).to_le_bytes());
        bytes[0x10C..0x110].copy_from_slice(&(0x100u32).to_le_bytes());
        bytes[0x188..0x190].copy_from_slice(b".text\0\0\0");
        bytes[0x190..0x194].copy_from_slice(&(0x2000u32).to_le_bytes());
        bytes[0x194..0x198].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[0x198..0x19C].copy_from_slice(&(0x2000u32).to_le_bytes());

        let metadata = parse_pe_metadata(&bytes).expect("parse pe metadata");
        assert_eq!(metadata.machine, Some(0x8664));
        assert_eq!(metadata.pe_timestamp, Some(0x12345678));
        assert_eq!(metadata.entry_point_rva, Some(0x2000));
        assert_eq!(metadata.image_base, Some(0x140000000));
        assert_eq!(metadata.image_size, Some(0x500000));
        assert_eq!(metadata.import_directory_rva, Some(0x3000));
        assert_eq!(metadata.sections.len(), 1);
        assert_eq!(metadata.sections[0].name, ".text");
    }
}
