use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use miden_lib::transaction::TransactionKernel;
use miden_objects::{
    account::{AccountComponent, StorageSlot},
    assembly::{Assembler, DefaultSourceManager, Library, LibraryPath, Module, ModuleKind},
};

/// MASM root set by build.rs
fn masm_root() -> PathBuf {
    PathBuf::from(env!("OZ_MASM_DIR"))
}

/// masm/auth folder path
fn auth_dir() -> PathBuf {
    masm_root().join("auth")
}

/// Recursively collects all `.masm` files under the given root directory.
fn collect_all_masm_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut dirs = vec![root.to_path_buf()];

    while let Some(dir) = dirs.pop() {
        if !dir.exists() {
            continue;
        }

        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("masm") {
                files.push(path);
            }
        }
    }

    Ok(files)
}

pub fn build_openzeppelin_library() -> Result<Library> {
    let root = masm_root();
    let masm_files = collect_all_masm_files(&root)?;

    let mut seen_names = HashSet::<String>::new();
    let mut modules = Vec::new();

    let sources = Arc::new(DefaultSourceManager::default());

    for path in masm_files {
        let stem = path
            .file_stem()
            .ok_or_else(|| anyhow!("invalid MASM path: {path:?}"))?
            .to_string_lossy()
            .to_string();

        // Bunlar account component olarak ayrı derleniyor, OZ lib’e koymana gerek yok
        if stem == "multisig" || stem == "timelocked_account" {
            continue;
        }

        if !seen_names.insert(stem.clone()) {
            return Err(anyhow!(
                "duplicate MASM module name '{stem}' under masm/; \
                 this would map to the same 'openzeppelin::{stem}' path"
            ));
        }

        let code = fs::read_to_string(&path)
            .map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;

        // *** KRİTİK KISIM ***
        // Her dosyayı açıkça `openzeppelin::<stem>` path’iyle modül olarak parse et
        let lib_path = LibraryPath::new(&format!("openzeppelin::{stem}"))
            .map_err(|e| anyhow!("invalid library path for {stem}: {e}"))?;

        let module = Module::parser(ModuleKind::Library)
            .parse_str(lib_path, &code, &sources.clone())
            .map_err(|e| anyhow!("failed to parse module openzeppelin::{stem} from {path:?}: {e}"))?;

        modules.push(module);
    }

    // TransactionKernel assembler + tüm OZ modüllerini tek bir Library olarak derle
    let assembler: Assembler = TransactionKernel::assembler().with_debug_mode(true);

    let library: Library = assembler
        .clone()
        .assemble_library(modules)
        .map_err(|e| anyhow!("failed to assemble openzeppelin library from masm/: {e}"))?;

    Ok(library)
}

/// Builds the assembler with the openzeppelin library linked.
fn build_assembler() -> Result<Assembler> {
    let oz_lib = build_openzeppelin_library()?;

    let asm: Assembler = TransactionKernel::assembler()
        .with_debug_mode(true)
        .with_dynamic_library(oz_lib)
        .map_err(|e| anyhow!("failed to link openzeppelin library: {e}"))?;

    Ok(asm)
}

// ============================================================================
// COMPONENT BUILDERS
// ============================================================================

/// Build AccountComponent from masm/auth/multisig.masm.
/// This component provides multi-signature authentication.
/// It requires the PSM component to be added separately if PSM verification is needed.
/// Assembler comes with the openzeppelin library (all modules) loaded.
///
/// Storage layout (4 slots):
/// - Slot 0: Threshold config [default_threshold, num_approvers, 0, 0]
/// - Slot 1: Approver public keys map
/// - Slot 2: Executed transactions map
/// - Slot 3: Procedure threshold overrides map
pub fn build_multisig_component(slots: Vec<StorageSlot>) -> Result<AccountComponent> {
    let asm = build_assembler()?;

    let path = auth_dir().join("multisig.masm");
    let code = fs::read_to_string(&path).map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;

    let component = AccountComponent::compile(code, asm, slots)?.with_supports_all_types();

    Ok(component)
}

/// Build AccountComponent from masm/auth/timelocked_account.masm.
/// This component provides multi-signature authentication with on-chain
/// timelocked key rotation (propose / execute / cancel).
/// It requires the PSM component to be added separately if PSM verification is needed.
/// Assembler comes with the openzeppelin library (all modules) loaded.
///
/// Storage layout (6 slots):
/// - Slot 0: Threshold config [default_threshold, num_approvers, 0, 0]
/// - Slot 1: Approver public keys map
/// - Slot 2: Executed transactions map
/// - Slot 3: Procedure threshold overrides map
/// - Slot 4: Key-rotation config [delay_blocks, 0, 0, 0]
/// - Slot 5: Key-rotation proposals map
pub fn build_timelocked_account_component(slots: Vec<StorageSlot>) -> Result<AccountComponent> {
    let asm = build_assembler()?;

    let path = auth_dir().join("timelocked_account.masm");
    let code = fs::read_to_string(&path).map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;

    let component = AccountComponent::compile(code, asm, slots)?.with_supports_all_types();

    Ok(component)
}

/// Build AccountComponent from masm/auth/psm.masm.
/// This component provides PSM (Private State Manager) signature verification.
///
/// Storage layout (2 slots):
/// - Slot 0: PSM selector [selector, 0, 0, 0] where selector=1 means ON, 0 means OFF
/// - Slot 1: PSM public key map
pub fn build_psm_component(slots: Vec<StorageSlot>) -> Result<AccountComponent> {
    let asm = build_assembler()?;

    let path = auth_dir().join("psm.masm");
    let code = fs::read_to_string(&path).map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;

    let component = AccountComponent::compile(code, asm, slots)?.with_supports_all_types();

    Ok(component)
}

/// Build Access component from masm/account/access.masm.
pub fn build_access_component(slots: Vec<StorageSlot>) -> Result<AccountComponent> {
    let asm = build_assembler()?;

    let path = masm_root().join("account").join("access.masm");
    let code = fs::read_to_string(&path).map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;

    let component = AccountComponent::compile(code, asm, slots)?.with_supports_all_types();

    Ok(component)
}

/// Creates a Library from the given MASM code and library path.
pub fn create_library(
    account_code: String,
    library_path: &str,
) -> Result<Library, Box<dyn std::error::Error>> {
    let assembler: Assembler = TransactionKernel::assembler().with_debug_mode(true);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let module = Module::parser(ModuleKind::Library).parse_str(
        LibraryPath::new(library_path)?,
        account_code,
        &source_manager,
    )?;
    let library = assembler.clone().assemble_library([module])?;
    Ok(library)
}

/// Builds the OpenZeppelin library for use in transaction scripts.
/// This library contains all MASM modules from the masm/ directory.
pub fn get_openzeppelin_library() -> Result<Library> {
    build_openzeppelin_library()
}

/// Builds a library for multisig procedures for use in transaction scripts.
/// The procedures are accessible via `call.::procedure_name` syntax.
pub fn get_multisig_library() -> Result<Library> {
    let path = auth_dir().join("multisig.masm");
    let code = fs::read_to_string(&path)
        .map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;

    // multisig.masm içinde PSM ve diğer OZ modülleri kullanılabiliyor.
    // Bu yüzden assembler'ın OpenZeppelin library'si ile link'lenmiş olması gerekiyor.
    let asm = build_assembler()?;

    let library = asm
        .assemble_library([code])
        .map_err(|e| anyhow!("failed to assemble multisig library: {e}"))?;

    Ok(library)
}

/// Builds a library for timelocked_account procedures for use in transaction scripts.
/// The procedures are accessible via `call.::procedure_name` syntax.
pub fn get_timelocked_account_library() -> Result<Library> {
    let path = auth_dir().join("timelocked_account.masm");
    let code = fs::read_to_string(&path)
        .map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;

    let asm = build_assembler()?;

    let library = asm
        .assemble_library([code])
        .map_err(|e| anyhow!("failed to assemble timelocked_account library: {e}"))?;

    Ok(library)
}

/// Builds a library for PSM procedures for use in transaction scripts.
/// The procedures are accessible via `call.::procedure_name` syntax.
pub fn get_psm_library() -> Result<Library> {
    let path = auth_dir().join("psm.masm");
    let code = fs::read_to_string(&path).map_err(|e| anyhow!("failed to read {path:?}: {e}"))?;

    // PSM tek başına da derlenebiliyor; burada ekstra OZ lib'e ihtiyaç yok.
    let assembler: Assembler = TransactionKernel::assembler().with_debug_mode(true);

    let library = assembler
        .assemble_library([code])
        .map_err(|e| anyhow!("failed to assemble PSM library: {e}"))?;

    Ok(library)
}
