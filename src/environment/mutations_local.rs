//! [`EnvironmentMutations`]-trait-shaped inherent methods on [`LocalFsStore`].
//!
//! Phase D PR-3a.2..3a.16 lands one verb group per PR here, each replacing
//! the matching `store.transact(env_id, |locked| …)` closure in `src/cli/*`
//! with a typed verb that can also be implemented by `HttpEnvironmentStore`
//! (PR-3b) over the A8 wire contract.
//!
//! The methods land as **inherent** (not the trait impl) so each PR can land
//! independently — Rust requires all trait methods to exist before a single
//! `impl EnvironmentMutations for LocalFsStore` block compiles. Once every
//! verb group has migrated (PR-3a.16), a trailing PR wires the trait impl as
//! thin forwarders.

use greentic_distributor_client::signing::TrustedKey;
use serde_json::{Value, json};

use greentic_deploy_spec::EnvId;

use super::mutations::TrustRootSeed;
use super::store::{LocalFsStore, StoreError};
use super::trust_root::{self as store_trust_root, trust_root_path};

impl LocalFsStore {
    // -------------------------------------------------------------
    // Trust root  (PR-3a.2)
    //   `op env trust-root bootstrap | add | remove`
    //   `op env init` calls `seed_trust_root_if_absent` for first-init only.
    // -------------------------------------------------------------

    /// Unconditional re-grant: load (or generate) the operator key and add
    /// it to the env trust root. Idempotent on case-insensitive key_id
    /// collision — the existing entry's PEM is overwritten with whatever
    /// the operator-key file holds today.
    ///
    /// **Lock placement.** `operator_key::load_or_generate` runs OUTSIDE the
    /// env flock so a slow OS RNG seed does not hold the lock; the trust-root
    /// mutation runs INSIDE the flock so concurrent `add`/`remove` cannot
    /// race the read-modify-write. Caller is responsible for any authz gate
    /// before invoking this method — `~/.greentic/operator/key.pem` is
    /// generated on first call to `load_or_generate`, so an authz failure
    /// after this method runs would not roll back that side effect.
    pub fn bootstrap_trust_root(&self, env_id: &EnvId) -> Result<TrustRootSeed, StoreError> {
        let op_key = crate::operator_key::load_or_generate()?;
        let env_dir = self.env_dir(env_id)?;
        self.transact(env_id, |_locked| -> Result<TrustRootSeed, StoreError> {
            let trust = store_trust_root::add_trusted_key(
                &env_dir,
                TrustedKey {
                    key_id: op_key.key_id.clone(),
                    public_key_pem: op_key.public_pem.clone(),
                },
            )?;
            Ok(TrustRootSeed {
                key_id: op_key.key_id.clone(),
                public_key_pem: op_key.public_pem.clone(),
                trusted_key_count: trust.keys.len(),
            })
        })
    }

    /// First-init-only variant: returns `None` when `<env_dir>/trust-root.json`
    /// already exists (operator has touched the trust root via
    /// bootstrap/add/remove). The existence check and `load_or_generate` both
    /// sit under the env flock so a concurrent `trust-root remove` cannot race
    /// the gate, and `~/.greentic/operator/key.pem` is not auto-generated when
    /// the gate would skip.
    pub fn seed_trust_root_if_absent(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<TrustRootSeed>, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        let tr_path = trust_root_path(&env_dir);
        self.transact(
            env_id,
            |_locked| -> Result<Option<TrustRootSeed>, StoreError> {
                if tr_path.exists() {
                    return Ok(None);
                }
                let op_key = crate::operator_key::load_or_generate()?;
                let trust = store_trust_root::add_trusted_key(
                    &env_dir,
                    TrustedKey {
                        key_id: op_key.key_id.clone(),
                        public_key_pem: op_key.public_pem.clone(),
                    },
                )?;
                Ok(Some(TrustRootSeed {
                    key_id: op_key.key_id,
                    public_key_pem: op_key.public_pem,
                    trusted_key_count: trust.keys.len(),
                }))
            },
        )
    }

    /// Add a trusted (key_id, public_key_pem) entry to the env trust root.
    /// Validates `key_id` matches the canonical derivation from `pem` and
    /// rejects empty/whitespace key ids. Idempotent on case-insensitive
    /// `key_id` collision. Returns the wire-shape JSON the CLI surfaces.
    pub fn add_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        public_key_pem: String,
    ) -> Result<Value, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        self.transact(env_id, |_locked| -> Result<Value, StoreError> {
            let trust = store_trust_root::add_trusted_key(
                &env_dir,
                TrustedKey {
                    key_id: key_id.clone(),
                    public_key_pem,
                },
            )?;
            Ok(json!({
                "environment_id": env_id.as_str(),
                "added_key_id": key_id,
                "trusted_key_count": trust.keys.len(),
            }))
        })
    }

    /// Remove a trusted key by case-insensitive `key_id`. Silent no-op when
    /// the id is absent. Returns the wire-shape JSON: the PEM that was
    /// actually removed (captured under the flock for race-safety) and the
    /// post-removal trusted-key count.
    pub fn remove_trusted_key(&self, env_id: &EnvId, key_id: String) -> Result<Value, StoreError> {
        let env_dir = self.env_dir(env_id)?;
        self.transact(env_id, |_locked| -> Result<Value, StoreError> {
            let pre = store_trust_root::load(&env_dir)?;
            let removed_pem = pre
                .keys
                .iter()
                .find(|k| k.key_id.eq_ignore_ascii_case(&key_id))
                .map(|k| k.public_key_pem.clone());
            let trust = store_trust_root::remove_trusted_key(&env_dir, &key_id)?;
            Ok(json!({
                "environment_id": env_id.as_str(),
                "removed_key_id": key_id,
                "removed_public_key_pem": removed_pem,
                "trusted_key_count": trust.keys.len(),
            }))
        })
    }
}
