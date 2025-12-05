use miden_objects::Word;
use miden_objects::assembly::Library;

use crate::masm_builder::{
    get_psm_library,
    get_timelocked_account_library,
};

use miden_lib::procedure_digest;

// INTERNAL LIBRARY HELPERS
fn psm_library() -> Library {
    get_psm_library().expect("failed to build PSM library for digest computation")
}

fn timelocked_account_library() -> Library {
    get_timelocked_account_library()
        .expect("failed to build timelocked_account library for digest computation")
}

// PSM PROCEDURES
procedure_digest!(
    PSM_UPDATE_PSM_PUBLIC_KEY,
    "update_psm_public_key",
    psm_library
);

pub mod psm {
    use super::*;

    pub const UPDATE_PSM_PUBLIC_KEY_PROC_NAME: &str = "update_psm_public_key";

    pub fn update_psm_public_key_digest() -> Word {
        *PSM_UPDATE_PSM_PUBLIC_KEY
    }
}

// TIMELOCKED ACCOUNT PROCEDURES
procedure_digest!(
    TIMELOCKED_PROPOSE_KEY_ROTATION,
    "propose_key_rotation",
    timelocked_account_library
);

procedure_digest!(
    TIMELOCKED_EXECUTE_KEY_ROTATION,
    "execute_key_rotation",
    timelocked_account_library
);

pub mod timelocked {
    use super::*;

    pub const PROPOSE_KEY_ROTATION_PROC_NAME: &str = "propose_key_rotation";
    pub const EXECUTE_KEY_ROTATION_PROC_NAME: &str = "execute_key_rotation";

    pub fn propose_key_rotation_digest() -> Word {
        *TIMELOCKED_PROPOSE_KEY_ROTATION
    }

    pub fn execute_key_rotation_digest() -> Word {
        *TIMELOCKED_EXECUTE_KEY_ROTATION
    }
}
