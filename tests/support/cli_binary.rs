use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn cli_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn copied_test_binary(_dir: &tempfile::TempDir) -> std::path::PathBuf {
    // Returns the cargo-built binary path directly. The historical per-test
    // copy was added to dodge `ExecutableFileBusy` when parallel tests hit
    // the same binary; once `cli_test_lock` started serializing CLI process
    // execution the copy became redundant — but it kept ~345 MB × 60 test
    // sites of disk pressure on CI runners, which now occasionally fail
    // with `StorageFull`. The TempDir argument is retained so the 60+ call
    // sites stay unchanged.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
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
