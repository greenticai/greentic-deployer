use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn cli_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn copied_test_binary(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_greentic-deployer"));
    let target = dir.path().join("greentic-deployer");
    std::fs::copy(source, &target).expect("copy greentic-deployer test binary");
    target
}

pub fn command_output_with_busy_retry(command: &mut Command) -> std::process::Output {
    let _guard = cli_test_lock()
        .lock()
        .expect("lock cli test process execution");
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
