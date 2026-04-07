use serde_json::{json, Value};

use crate::domain::address::{AddressRef, AddressSource};
use crate::runtime;

use super::util;

pub fn normalize_address_from_modules(
    address: usize,
    modules: &[runtime::ModuleInfo],
) -> Option<AddressRef> {
    let module = find_module_for_address(address, modules)?;
    let rva = address.saturating_sub(module.base_address);

    Some(AddressRef {
        module_name: module.name.clone(),
        module_base: util::format_address(module.base_address),
        va: util::format_address(address),
        rva: util::format_rva(rva),
        file_offset: None,
        arch: "x64".to_owned(),
        source: AddressSource::Runtime,
    })
}

pub fn normalized_module_metadata(module: &runtime::ModuleInfo) -> Value {
    json!({
        "module_name": module.name,
        "module_base": util::format_address(module.base_address),
        "arch": "x64",
        "source": "runtime"
    })
}

pub fn find_module_for_address<'a>(
    address: usize,
    modules: &'a [runtime::ModuleInfo],
) -> Option<&'a runtime::ModuleInfo> {
    modules.iter().find(|module| {
        let start = module.base_address;
        let end = start.saturating_add(module.size as usize);
        start <= address && address < end
    })
}
