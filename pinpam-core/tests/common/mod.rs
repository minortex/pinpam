//! swtpm-based test harness.
//!
//! Each test that needs a TPM calls [`try_start_swtpm`]. When `swtpm` is not
//! installed, the helper returns `None` and the test prints a skip line.
//! Otherwise, it spawns an isolated `swtpm` instance bound to a free TCP
//! port pair with a fresh state directory. The instance is killed when the
//! returned [`Swtpm`] is dropped.

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub struct Swtpm {
    child: Child,
    port: u16,
    state_dir: tempfile::TempDir,
}

impl Swtpm {
    pub fn tcti_spec(&self) -> String {
        // The `swtpm` TCTI talks to swtpm directly (skipping the legacy mssim
        // power-on/NV-enable handshake), which is what `--flags not-need-init,
        // startup-clear` expects.
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    /// Stop swtpm but keep the state directory alive so a future invocation
    /// can rehydrate from it. The returned handle owns the TempDir.
    pub fn into_persisted_state(mut self) -> tempfile::TempDir {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Move the TempDir out without running our Drop.
        let dir = std::mem::replace(
            &mut self.state_dir,
            tempfile::tempdir().expect("placeholder tempdir"),
        );
        std::mem::forget(self);
        dir
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether `swtpm` is available on PATH. Cached so we only probe once.
fn swtpm_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Command::new("swtpm")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Start swtpm in a brand new state directory. Returns `None` when swtpm is
/// not installed so callers can gracefully skip.
pub fn try_start_swtpm() -> Option<Swtpm> {
    if !swtpm_available() {
        eprintln!("swtpm not installed - skipping integration test");
        return None;
    }
    Some(start_swtpm_in(tempfile::tempdir().expect("create tempdir")))
}

/// Start swtpm, reusing an existing state directory. Use this to simulate a
/// reboot: drop the previous Swtpm with `into_persisted_state`, then pass the
/// returned TempDir back in.
pub fn try_resume_swtpm(state_dir: tempfile::TempDir) -> Option<Swtpm> {
    if !swtpm_available() {
        eprintln!("swtpm not installed - skipping integration test");
        return None;
    }
    Some(start_swtpm_in(state_dir))
}

fn start_swtpm_in(state_dir: tempfile::TempDir) -> Swtpm {
    let (port, ctrl_port) = pick_consecutive_free_ports();

    let child = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
        ])
        .arg(format!("dir={}", state_dir.path().display()))
        .args([
            "--server",
        ])
        .arg(format!("type=tcp,port={}", port))
        .args([
            "--ctrl",
        ])
        .arg(format!("type=tcp,port={}", ctrl_port))
        .args(["--flags", "not-need-init,startup-clear"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn swtpm");

    wait_until_ready(port);
    Swtpm {
        child,
        port,
        state_dir,
    }
}

/// Pick two consecutive free TCP ports. The `swtpm` TCTI assumes the control
/// port is `data_port + 1`, so we must allocate them as a pair.
fn pick_consecutive_free_ports() -> (u16, u16) {
    for _ in 0..32 {
        let data = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let data_port = data.local_addr().expect("addr").port();
        if data_port == u16::MAX {
            continue;
        }
        // Try to grab port+1 while still holding port to avoid another caller
        // claiming the data port between drops.
        match TcpListener::bind(("127.0.0.1", data_port + 1)) {
            Ok(ctrl) => {
                let ctrl_port = ctrl.local_addr().expect("addr").port();
                drop(ctrl);
                drop(data);
                return (data_port, ctrl_port);
            }
            Err(_) => continue,
        }
    }
    panic!("could not find a free TCP port pair for swtpm");
}

fn wait_until_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect_timeout(
            &(([127, 0, 0, 1], port).into()),
            Duration::from_millis(200),
        ) {
            Ok(_) => return,
            Err(e)
                if e.kind() == ErrorKind::ConnectionRefused
                    || e.kind() == ErrorKind::ConnectionReset
                    || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => panic!("unexpected error connecting to swtpm: {e}"),
        }
        if Instant::now() >= deadline {
            panic!("swtpm did not become ready on port {port}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
