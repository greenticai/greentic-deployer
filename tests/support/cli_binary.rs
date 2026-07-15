use std::process::Command;
use std::time::Duration;

pub fn copied_test_binary(_dir: &tempfile::TempDir) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

pub fn command_output_with_busy_retry(command: &mut Command) -> std::process::Output {
    let state_dir = tempfile::tempdir().expect("create per-invocation state dir");
    command.env("GREENTIC_PATHS_STATE_DIR", state_dir.path());
    let mut attempts = 0;
    loop {
        match command.output() {
            Ok(output) => return output,
            Err(err) if err.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 5 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => panic!("run greentic-deployer: {err}"),
        }
    }
}
