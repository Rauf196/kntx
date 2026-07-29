//! Startup failure semantics. Runs the real binary because startup lives in
//! `main::run` behind `#[tokio::main]` + arg parsing, and the property under test
//! is process-level: exit code and what was left serving.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn bind_failure_at_startup_fails_fast() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = occupied.local_addr().unwrap();
    // declared before the busy one, so a startup that served listeners as it bound
    // them would leave this one accepting traffic.
    let free = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    write!(
        config,
        "[[listeners]]\naddress = \"{free}\"\nmode = \"l4\"\npool = \"web\"\n\n\
         [[listeners]]\naddress = \"{busy}\"\nmode = \"l4\"\npool = \"web\"\n\n\
         [[pools]]\nname = \"web\"\nbackends = [{{ address = \"127.0.0.1:9\" }}]\n"
    )
    .unwrap();
    config.flush().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kntx"))
        .arg("--config")
        .arg(config.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("still running with {busy} occupied - startup did not fail fast");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    assert!(!status.success(), "expected non-zero exit, got {status}");

    let stderr = String::from_utf8_lossy(&child.wait_with_output().unwrap().stderr).into_owned();
    assert!(
        stderr.contains(&format!("failed to bind to {busy}")),
        "bind failure not reported on stderr: {stderr}"
    );

    assert!(
        TcpStream::connect(free).is_err(),
        "peer listener {free} still accepting after startup failed"
    );
}
