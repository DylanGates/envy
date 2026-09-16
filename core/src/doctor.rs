//! `envy doctor` (see `docs/feature-proposals.md`'s new-idea #1, directly
//! motivated by the 2026-09-15/16 keychain-persistence bug in
//! `docs/LESSONS.md`, which took a full manual live-example investigation
//! to catch). Runs the same `init` → re-`init` → `add` → `get` sequence
//! that diagnosed that bug by hand, against a throwaway vault and a real,
//! uniquely-named keychain entry this module creates and deletes itself —
//! it never opens or touches a real project's vault, so it's safe to run
//! any time, including automatically.

use crate::keychain::{KeyStore, OsKeychain};

/// The outcome of one diagnostic step. `Ok` carries a short human-readable
/// detail; `Err` a short human-readable failure reason. Never panics —
/// every step is caught so one failure doesn't stop the rest of the run.
pub struct DoctorStep {
    pub name: &'static str,
    pub outcome: Result<String, String>,
}

pub struct DoctorReport {
    pub steps: Vec<DoctorStep>,
}

impl DoctorReport {
    /// True if every step that isn't purely informational passed.
    pub fn all_passed(&self) -> bool {
        self.steps.iter().all(|s| s.outcome.is_ok())
    }
}

/// Runs the full diagnostic sequence and returns a report. Steps run
/// independently: a failure in `add` still lets `cleanup` run (best-effort,
/// so a doctor run never leaks a temp dir or keychain entry), but `get` is
/// reported as skipped rather than attempted, since it has nothing to
/// round-trip.
pub fn run() -> DoctorReport {
    let mut steps = Vec::new();

    steps.push(DoctorStep {
        name: "environment",
        outcome: Ok(format!(
            "os={}, keychain_backend=keyring 2.x (security-framework / Windows Credential Manager / Secret Service)",
            std::env::consts::OS
        )),
    });

    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            steps.push(DoctorStep {
                name: "init",
                outcome: Err(format!("could not create a temp directory: {e}")),
            });
            return DoctorReport { steps };
        }
    };

    let keystore = OsKeychain;
    let first_vault = match crate::vault::init_with_keystore(dir.path(), &keystore) {
        Ok(vault) => {
            steps.push(DoctorStep {
                name: "init",
                outcome: Ok(format!("created vault {}", vault.vault_id)),
            });
            Some(vault)
        }
        Err(e) => {
            steps.push(DoctorStep {
                name: "init",
                outcome: Err(e.to_string()),
            });
            None
        }
    };

    let vault_id = first_vault.as_ref().map(|v| v.vault_id.clone());

    match (&first_vault, crate::vault::init_with_keystore(dir.path(), &keystore)) {
        (Some(first), Ok(second)) if first.vault_id == second.vault_id => {
            steps.push(DoctorStep {
                name: "re-init (idempotency)",
                outcome: Ok("second init returned the same vault".to_string()),
            });
        }
        (Some(_), Ok(second)) => {
            steps.push(DoctorStep {
                name: "re-init (idempotency)",
                outcome: Err(format!("re-init returned a different vault id: {}", second.vault_id)),
            });
        }
        (None, _) => {
            steps.push(DoctorStep {
                name: "re-init (idempotency)",
                outcome: Err("skipped: init failed".to_string()),
            });
        }
        (Some(_), Err(e)) => {
            steps.push(DoctorStep {
                name: "re-init (idempotency)",
                outcome: Err(e.to_string()),
            });
        }
    }

    const PROBE_NAME: &str = "DOCTOR_PROBE";
    const PROBE_VALUE: &[u8] = b"doctor-probe-value";

    let add_ok = match &first_vault {
        Some(vault) => match vault.add_secret(PROBE_NAME, PROBE_VALUE) {
            Ok(()) => {
                steps.push(DoctorStep {
                    name: "add",
                    outcome: Ok("stored a probe secret".to_string()),
                });
                true
            }
            Err(e) => {
                steps.push(DoctorStep {
                    name: "add",
                    outcome: Err(e.to_string()),
                });
                false
            }
        },
        None => {
            steps.push(DoctorStep {
                name: "add",
                outcome: Err("skipped: init failed".to_string()),
            });
            false
        }
    };

    if add_ok {
        match first_vault.as_ref().unwrap().get_secret(PROBE_NAME) {
            Ok(value) if value == PROBE_VALUE => {
                steps.push(DoctorStep {
                    name: "get (keychain round-trip)",
                    outcome: Ok("probe secret round-tripped correctly".to_string()),
                });
            }
            Ok(_) => {
                steps.push(DoctorStep {
                    name: "get (keychain round-trip)",
                    outcome: Err("decrypted value did not match what was stored".to_string()),
                });
            }
            Err(e) => {
                steps.push(DoctorStep {
                    name: "get (keychain round-trip)",
                    outcome: Err(e.to_string()),
                });
            }
        }
    } else {
        steps.push(DoctorStep {
            name: "get (keychain round-trip)",
            outcome: Err("skipped: add failed".to_string()),
        });
    }

    // Best-effort cleanup of the keychain entry, always attempted
    // regardless of what failed above — a doctor run must never leave an
    // orphaned keychain entry behind. The temp directory itself cleans up
    // via `TempDir`'s `Drop` when `dir` goes out of scope at the end of
    // this function (same pattern every test in this crate already relies
    // on — no need to reimplement it here).
    drop(first_vault);
    steps.push(DoctorStep {
        name: "cleanup",
        outcome: match &vault_id {
            Some(vault_id) => match keystore.delete_key(vault_id) {
                Ok(()) => Ok("removed the diagnostic keychain entry".to_string()),
                Err(e) => Err(format!("keychain entry: {e}")),
            },
            None => Ok("nothing to clean up: init never created a keychain entry".to_string()),
        },
    });

    DoctorReport { steps }
}
