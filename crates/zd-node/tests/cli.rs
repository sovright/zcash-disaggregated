//! The `zd` binary end to end: three participants generate identities, agree
//! on parameters, run a 2-of-3 key ceremony through a relay process, and the
//! resulting account goes into a wallet database. Then a FROST coordinator
//! and an address service start from the ceremony's files.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn zd() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_zd"));
    c.env("RUST_LOG", "warn");
    c
}

fn ok(o: Output) -> String {
    assert!(
        o.status.success(),
        "zd failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_port(port: u16) {
    let start = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "server did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

#[test]
fn ceremony_to_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    for id in 1..=3 {
        let entry = ok(zd()
            .args(["identity", "keygen", "--instance"])
            .arg(format!("member-{id}"))
            .args(["--id", &id.to_string(), "--out"])
            .arg(d.join(format!("id{id}.toml")))
            .output()
            .unwrap());
        assert!(entry.contains("[[participant]]"));
        std::fs::write(d.join(format!("p{id}.toml")), entry).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join(format!("id{id}.toml")))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
    let out = ok(zd()
        .args([
            "ceremony",
            "params",
            "--threshold",
            "2",
            "--network",
            "test",
            "--label",
            "treasury",
        ])
        .args(["--participant"])
        .arg(d.join("p1.toml"))
        .args(["--participant"])
        .arg(d.join("p2.toml"))
        .args(["--participant"])
        .arg(d.join("p3.toml"))
        .arg("--out")
        .arg(d.join("params.toml"))
        .output()
        .unwrap());
    assert!(out.starts_with("transcript id "));

    let port = free_port();
    let _relay = Kill(
        zd().args(["ceremony", "relay", "--listen"])
            .arg(format!("127.0.0.1:{port}"))
            .arg("--params")
            .arg(d.join("params.toml"))
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_port(port);

    let joins: Vec<Child> = (1..=3)
        .map(|id| {
            zd().args(["ceremony", "join", "--relay"])
                .arg(format!("http://127.0.0.1:{port}"))
                .arg("--params")
                .arg(d.join("params.toml"))
                .arg("--identity")
                .arg(d.join(format!("id{id}.toml")))
                .args(["--me", &id.to_string(), "--out"])
                .arg(d.join(format!("m{id}")))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for j in joins {
        ok(j.wait_with_output().unwrap());
    }

    // Everyone agrees on the account; key packages differ.
    let acct = read(&d.join("m1/account.toml"));
    assert!(acct.contains("uviewtest1"));
    for id in 2..=3 {
        assert_eq!(read(&d.join(format!("m{id}/account.toml"))), acct);
        assert_ne!(
            read(&d.join(format!("m{id}/frost-member.toml"))),
            read(&d.join("m1/frost-member.toml"))
        );
        assert_eq!(
            read(&d.join(format!("m{id}/recovery.toml"))),
            read(&d.join("m1/recovery.toml"))
        );
    }

    let added = ok(zd()
        .args(["wallet", "add-account", "--db"])
        .arg(d.join("wallet.db"))
        .arg("--account")
        .arg(d.join("m1/account.toml"))
        .args(["--birthday", "3500000"])
        .output()
        .unwrap());
    assert!(added.starts_with("added "));

    // The other roles start from the ceremony's files.
    let coord = free_port();
    let _coordinator = Kill(
        zd().args(["frost-coordinator", "--listen"])
            .arg(format!("127.0.0.1:{coord}"))
            .arg("--account")
            .arg(d.join("m1/account.toml"))
            .args([
                "--member",
                "http://127.0.0.1:1",
                "--member",
                "http://127.0.0.1:2",
            ])
            .spawn()
            .unwrap(),
    );
    let member = free_port();
    let _member = Kill(
        zd().args(["frost-member", "--listen"])
            .arg(format!("127.0.0.1:{member}"))
            .arg("--key-package")
            .arg(d.join("m2/frost-member.toml"))
            .spawn()
            .unwrap(),
    );
    let addr = free_port();
    let _address = Kill(
        zd().args(["address", "--listen"])
            .arg(format!("127.0.0.1:{addr}"))
            .args(["--server-id", "7", "--account"])
            .arg(d.join("m1/account.toml"))
            .arg("--counters")
            .arg(d.join("counters"))
            .spawn()
            .unwrap(),
    );
    wait_for_port(coord);
    wait_for_port(member);
    wait_for_port(addr);

    let new_address = || {
        ok(zd()
            .args(["new-address", "--server"])
            .arg(format!("http://127.0.0.1:{addr}"))
            .arg("--account")
            .arg(d.join("m1/account.toml"))
            .output()
            .unwrap())
    };
    let a1 = new_address();
    let a2 = new_address();
    assert!(a1.starts_with("utest1"));
    assert_ne!(a1, a2);
    let fp = acct
        .lines()
        .find_map(|l| l.strip_prefix("fingerprint = \""))
        .unwrap()
        .trim_end_matches('"');
    assert_eq!(read(&d.join("counters").join(fp)), "2");
}
