//! `gen-schemas` — writes every top-level spec schema as `*.schema.json` into a
//! target directory (default: `target/schemas`).
//!
//! Currently emits an empty set because the schemars derives are not yet wired
//! across the spec types. See `json_schema.rs` for the deferral note.

use greentic_deploy_spec::json_schema::dump_all_schemas;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/schemas"));

    if let Err(err) = fs::create_dir_all(&out_dir) {
        eprintln!("failed to create {}: {err}", out_dir.display());
        return ExitCode::FAILURE;
    }

    let schemas = dump_all_schemas();
    if schemas.is_empty() {
        eprintln!("note: schemars derives not yet wired — see json_schema.rs. Nothing to emit.");
    }

    for (name, schema) in schemas {
        let path = out_dir.join(format!("{name}.schema.json"));
        let body = match serde_json::to_string_pretty(&schema) {
            Ok(body) => body,
            Err(err) => {
                eprintln!("failed to serialize {name}: {err}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(err) = fs::write(&path, body) {
            eprintln!("failed to write {}: {err}", path.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", path.display());
    }

    ExitCode::SUCCESS
}
