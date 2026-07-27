//! Give a bundle with a webchat backend and no browser tier the standard SPA.
//!
//! `messaging-webchat-gui` ships the SPA *and* a webchat provider, which makes
//! it an alternative to `messaging-webchat`, never an addition — two webchat
//! providers in one bundle both claim the same endpoints. A bundle on the plain
//! pack therefore has a working DirectLine backend and no page, and swapping the
//! packs is not equivalent (the plain pack carries diagnostics, webhook-verify
//! and subscription-sync flows the GUI pack does not).
//!
//! `messaging-webchat-ui` closes that gap: the SPA with no components, no
//! provider and no flows. Staging it into such a revision's `pack-list.lock`
//! gives the bundle a browser tier with no new runtime mechanism —
//! `greentic-start` discovers its static route like any other pack's and stamps
//! it with the consuming revision's scope, so the SPA is served under the real
//! bundle's URL and talks to that bundle's DirectLine endpoint.

use std::path::{Path, PathBuf};

use super::OpError;

/// Public-path prefix that marks a static route as a webchat browser tier.
const WEBCHAT_ROUTE_PREFIX: &str = "/v1/web/webchat";

/// Directory under the env root holding platform-supplied packs, resolved once
/// at env init and reused by every later stage. Keeps staging a purely local
/// operation: `terraform init` fetches and pins, `apply` runs offline.
pub const PLATFORM_PACKS_DIR: &str = "platform-packs";

/// File name of the cached UI pack. Load-bearing: `pack-list.lock` derives each
/// pack id from the file stem, not the manifest.
pub const WEBCHAT_UI_PACK_FILE: &str = "messaging-webchat-ui.gtpack";

/// What a pack contributes to a bundle's webchat story.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WebchatFacts {
    /// Declares a `greentic.static-routes.v1` route under `/v1/web/webchat`.
    pub serves_ui: bool,
    /// Declares `greentic.provider-extension.v1` with a webchat `provider_type`.
    pub serves_provider: bool,
}

impl WebchatFacts {
    fn merge(self, other: Self) -> Self {
        Self {
            serves_ui: self.serves_ui || other.serves_ui,
            serves_provider: self.serves_provider || other.serves_provider,
        }
    }

    /// A backend with no page. Both halves are load-bearing: without
    /// `!serves_ui` the injected route duplicates the GUI pack's public path
    /// and route validation fails the revision at boot; without
    /// `serves_provider` a Telegram-only bundle gets a page with no DirectLine
    /// endpoint behind it.
    fn needs_ui(self) -> bool {
        self.serves_provider && !self.serves_ui
    }
}

/// Read one pack's `manifest.cbor` and report what it contributes.
///
/// An unreadable pack reports nothing rather than failing the stage: staging
/// already digest-pins whatever it finds, and a pack this cannot parse is a
/// pack whose webchat intentions are unknown — the conservative answer is "adds
/// neither", which at worst skips the injection.
///
/// Delegates to the canonical reader so both TAR and ZIP archives are handled.
fn pack_webchat_facts(pack_path: &Path) -> WebchatFacts {
    let Ok(bytes) =
        crate::pack_introspect::read_entry_from_gtpack(pack_path, Path::new("manifest.cbor"))
    else {
        return WebchatFacts::default();
    };
    let Ok(value) = ciborium::from_reader::<ciborium::Value, _>(bytes.as_slice()) else {
        return WebchatFacts::default();
    };
    facts_from_manifest(&value)
}

/// Extension-map inspection, split out so it is testable without a `.gtpack`.
fn facts_from_manifest(value: &ciborium::Value) -> WebchatFacts {
    let Some(extensions) = lookup(value, "extensions") else {
        return WebchatFacts::default();
    };
    let Some(entries) = extensions.as_map() else {
        return WebchatFacts::default();
    };
    let mut facts = WebchatFacts::default();
    for (key, ext) in entries {
        let Some(name) = key.as_text() else { continue };
        match name {
            "greentic.provider-extension.v1" => {
                facts.serves_provider |= declares_webchat_provider(ext);
            }
            "greentic.static-routes.v1" => {
                facts.serves_ui |= declares_webchat_route(ext);
            }
            _ => {}
        }
    }
    facts
}

/// Whether any element of `ext.inline.<array_key>[].<field>` starts with
/// `prefix`. Both the provider and the static-route checks share this shape.
fn inline_array_has(ext: &ciborium::Value, array_key: &str, field: &str, prefix: &str) -> bool {
    let items = lookup(ext, "inline")
        .and_then(|inline| lookup(inline, array_key))
        .and_then(ciborium::Value::as_array);
    let Some(items) = items else { return false };
    items.iter().any(|item| {
        lookup(item, field)
            .and_then(ciborium::Value::as_text)
            .is_some_and(|t| t.starts_with(prefix))
    })
}

/// Whether a `greentic.provider-extension.v1` extension declares a webchat
/// provider. `messaging.provider_ingress.v1` is shared by every messaging
/// provider (Telegram, Teams, webchat, ...), so checking it alone would inject
/// the SPA into non-webchat bundles. The `provider_type` inside
/// `greentic.provider-extension.v1` is the typed identity.
fn declares_webchat_provider(ext: &ciborium::Value) -> bool {
    inline_array_has(ext, "providers", "provider_type", "messaging.webchat")
}

/// Whether a `greentic.static-routes.v1` extension declares a route under the
/// webchat prefix. A pack can declare static routes for something else
/// entirely, so the prefix — not the extension's presence — is the test.
fn declares_webchat_route(ext: &ciborium::Value) -> bool {
    inline_array_has(ext, "routes", "public_path", WEBCHAT_ROUTE_PREFIX)
}

fn lookup<'a>(value: &'a ciborium::Value, key: &str) -> Option<&'a ciborium::Value> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// Whether `packs` describes a bundle that has a webchat backend but no page.
pub fn needs_webchat_ui(packs: &[PathBuf]) -> bool {
    packs
        .iter()
        .map(|path| pack_webchat_facts(path))
        .fold(WebchatFacts::default(), WebchatFacts::merge)
        .needs_ui()
}

/// The cached platform UI pack for this env, when env init resolved one.
pub fn cached_ui_pack(env_dir: &Path) -> Option<PathBuf> {
    let path = env_dir.join(PLATFORM_PACKS_DIR).join(WEBCHAT_UI_PACK_FILE);
    path.is_file().then_some(path)
}

/// Copy the cached UI pack into `dest_dir` and return its path, for staging
/// into the revision alongside the bundle's own packs.
///
/// Copied rather than referenced in place so the revision stays self-contained:
/// `stage_local_bundle` pins every pack by a path relative to the env dir and a
/// sha256, and a revision must not depend on a shared cache entry that a later
/// env init could replace underneath it.
pub fn stage_ui_pack(cached: &Path, dest_dir: &Path) -> Result<PathBuf, OpError> {
    std::fs::create_dir_all(dest_dir).map_err(|source| OpError::Io {
        path: dest_dir.to_path_buf(),
        source,
    })?;
    let dest = dest_dir.join(WEBCHAT_UI_PACK_FILE);
    std::fs::copy(cached, &dest).map_err(|source| OpError::Io {
        path: dest.clone(),
        source,
    })?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    fn inline_ext(ext_name: &str, array_key: &str, field: &str, value: &str) -> (Value, Value) {
        (
            text(ext_name),
            Value::Map(vec![(
                text("inline"),
                Value::Map(vec![(
                    text(array_key),
                    Value::Array(vec![Value::Map(vec![(text(field), text(value))])]),
                )]),
            )]),
        )
    }

    fn static_routes_ext(public_path: &str) -> (Value, Value) {
        inline_ext(
            "greentic.static-routes.v1",
            "routes",
            "public_path",
            public_path,
        )
    }

    fn provider_ext(provider_type: &str) -> (Value, Value) {
        inline_ext(
            "greentic.provider-extension.v1",
            "providers",
            "provider_type",
            provider_type,
        )
    }

    fn manifest(exts: Vec<(Value, Value)>) -> Value {
        Value::Map(vec![(text("extensions"), Value::Map(exts))])
    }

    #[test]
    fn a_pack_with_a_webchat_route_serves_a_ui() {
        let facts = facts_from_manifest(&manifest(vec![static_routes_ext(
            "/v1/web/webchat/{tenant}",
        )]));
        assert!(facts.serves_ui);
        assert!(!facts.serves_provider);
    }

    /// A pack may ship static routes for something that is not webchat; the
    /// extension's presence is not the test, the public path is.
    #[test]
    fn static_routes_for_another_path_do_not_count_as_a_webchat_ui() {
        let facts = facts_from_manifest(&manifest(vec![static_routes_ext("/v1/web/admin")]));
        assert!(!facts.serves_ui);
    }

    #[test]
    fn a_webchat_provider_extension_serves_a_provider() {
        let facts = facts_from_manifest(&manifest(vec![provider_ext("messaging.webchat")]));
        assert!(facts.serves_provider);
        assert!(!facts.serves_ui);
    }

    /// `messaging.provider_ingress.v1` is shared across all messaging
    /// providers; without a webchat `provider_type` it must not trigger
    /// injection.
    #[test]
    fn a_generic_provider_ingress_does_not_count_as_webchat() {
        let facts = facts_from_manifest(&manifest(vec![(
            text("messaging.provider_ingress.v1"),
            Value::Map(vec![]),
        )]));
        assert!(!facts.serves_provider);
    }

    /// A Telegram-only bundle declares `messaging.provider_ingress.v1` and
    /// `greentic.provider-extension.v1` with `provider_type:
    /// "messaging.telegram.bot"` — it must NOT get a webchat SPA.
    #[test]
    fn a_telegram_provider_does_not_trigger_injection() {
        let facts = facts_from_manifest(&manifest(vec![
            provider_ext("messaging.telegram.bot"),
            (text("messaging.provider_ingress.v1"), Value::Map(vec![])),
        ]));
        assert!(!facts.serves_provider);
        assert!(!facts.needs_ui());
    }

    #[test]
    fn a_manifest_without_extensions_contributes_nothing() {
        assert_eq!(
            facts_from_manifest(&Value::Map(vec![])),
            WebchatFacts::default()
        );
        assert_eq!(
            facts_from_manifest(&Value::Text("not a map".into())),
            WebchatFacts::default()
        );
    }

    /// The GUI pack: provider AND UI in one. Injecting alongside it would
    /// duplicate the public path and fail route validation at boot.
    #[test]
    fn a_pack_serving_both_needs_no_injection() {
        let facts = facts_from_manifest(&manifest(vec![
            static_routes_ext("/v1/web/webchat/{tenant}"),
            provider_ext("messaging.webchat"),
        ]));
        assert!(facts.serves_ui && facts.serves_provider);
        assert!(!facts.needs_ui());
    }

    /// The case this whole feature exists for: the plain webchat pack.
    #[test]
    fn a_provider_without_a_ui_needs_the_injection() {
        let facts = facts_from_manifest(&manifest(vec![provider_ext("messaging.webchat")]));
        assert!(facts.needs_ui());
    }

    /// A Telegram-only bundle must NOT get a page: there is no DirectLine
    /// endpoint behind it. A UI-only bundle must not either — nothing to talk to.
    #[test]
    fn a_bundle_with_no_webchat_backend_gets_no_page() {
        assert!(!WebchatFacts::default().needs_ui());
        assert!(
            !WebchatFacts {
                serves_ui: true,
                serves_provider: false,
            }
            .needs_ui()
        );
    }

    #[test]
    fn merge_is_a_union_across_the_bundles_packs() {
        let ui = WebchatFacts {
            serves_ui: true,
            serves_provider: false,
        };
        let provider = WebchatFacts {
            serves_ui: false,
            serves_provider: true,
        };
        let both = ui.merge(provider);
        assert!(both.serves_ui && both.serves_provider);
    }

    #[test]
    fn an_unreadable_pack_contributes_nothing() {
        assert_eq!(
            pack_webchat_facts(Path::new("/nonexistent/nope.gtpack")),
            WebchatFacts::default()
        );
    }

    #[test]
    fn cached_ui_pack_is_none_without_an_env_init_resolve() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(cached_ui_pack(dir.path()).is_none());
    }
}
