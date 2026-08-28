// Not run on Windows. The test binary dies at load time with STATUS_ENTRYPOINT_NOT_FOUND before
// a single test starts — an export mismatch inside Tauri's mock runtime, not a missing file:
// CI confirmed `target/debug` contains no DLLs at all, so there is nothing to put on PATH.
//
// What is lost is nothing platform-specific. This file checks command names, argument shapes and
// error codes, all of it Rust with no `cfg` branch in sight, and Linux and macOS run every one of
// them. The Windows-only code — `create_private`, `sync_parent_directory`, the clipboard
// exclusion — lives in the library, whose 133 tests do run on Windows.
#![cfg(not(windows))]

//! Drives the command layer through Tauri's real invoke handler.
//!
//! The session underneath is covered by its own unit tests, and the adapters in `commands.rs`
//! are thin — but "thin" is not "verified". A wrong command name, a mismatched argument, or an
//! error that fails to serialize would all compile cleanly and only fail once a human clicked
//! something. This is the layer that catches those.

use std::sync::Mutex;
use std::time::Duration;

use password_manager_lib::commands::{self, AppState};
use password_manager_lib::crypto::kdf::KdfParams;
use password_manager_lib::session::Session;
use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{Manager, WebviewWindowBuilder};
use tempfile::TempDir;

const MASTER: &str = "a long enough master password";

struct Harness {
    webview: tauri::WebviewWindow<tauri::test::MockRuntime>,
    _app: tauri::App<tauri::test::MockRuntime>,
    _dir: TempDir,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().expect("temp dir");

        let app = mock_builder()
            .invoke_handler(tauri::generate_handler![
                commands::minimum_master_password_length,
                commands::vault_exists,
                commands::is_unlocked,
                commands::create_vault,
                commands::unlock,
                commands::lock,
                commands::reset_vault,
                commands::change_master_password,
                commands::list_entries,
                commands::reveal_entry,
                commands::add_entry,
                commands::update_entry,
                commands::remove_entry,
                commands::generate_password,
            ])
            .build(mock_context(noop_assets()))
            .expect("mock app");

        app.manage(AppState(Mutex::new(Session::new(
            dir.path().join("vault.pwm"),
            Duration::from_secs(300),
            // Real cost would add a fifth of a second to every call in this file.
            KdfParams::new(8, 1, 1).expect("cheap test parameters must be valid"),
        ))));

        // One webview per harness: labels are unique within an app, so building a fresh one per
        // call fails on the second command.
        let webview = WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("webview");

        Self {
            webview,
            _app: app,
            _dir: dir,
        }
    }

    /// Sends a command exactly as the WebView would, and returns whatever came back.
    fn call(&self, command: &str, args: Value) -> Result<Value, Value> {
        get_ipc_response(
            &self.webview,
            InvokeRequest {
                cmd: command.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: "tauri://localhost".parse().unwrap(),
                body: InvokeBody::Json(args),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.to_string(),
            },
        )
        .map(|body| body.deserialize::<Value>().expect("a JSON response"))
    }

    fn ok(&self, command: &str, args: Value) -> Value {
        self.call(command, args)
            .unwrap_or_else(|error| panic!("{command} failed: {error}"))
    }

    fn error_code(&self, command: &str, args: Value) -> String {
        let error = self
            .call(command, args)
            .expect_err("the command should have failed");

        error["code"].as_str().expect("a code field").to_owned()
    }
}

fn draft(site: &str, username: &str, password: &str) -> Value {
    json!({ "site": site, "username": username, "password": password, "notes": "" })
}

#[test]
fn reports_the_minimum_master_password_length() {
    let harness = Harness::new();

    assert!(
        harness
            .ok("minimum_master_password_length", json!({}))
            .as_u64()
            >= Some(12)
    );
}

#[test]
fn a_fresh_installation_has_no_vault_and_is_locked() {
    let harness = Harness::new();

    assert_eq!(harness.ok("vault_exists", json!({})), json!(false));
    assert_eq!(harness.ok("is_unlocked", json!({})), json!(false));
}

#[test]
fn creates_unlocks_and_locks_a_vault() {
    let harness = Harness::new();

    harness.ok("create_vault", json!({ "password": MASTER }));
    assert_eq!(harness.ok("vault_exists", json!({})), json!(true));
    assert_eq!(harness.ok("is_unlocked", json!({})), json!(true));

    harness.ok("lock", json!({}));
    assert_eq!(harness.ok("is_unlocked", json!({})), json!(false));

    harness.ok("unlock", json!({ "password": MASTER }));
    assert_eq!(harness.ok("is_unlocked", json!({})), json!(true));
}

#[test]
fn refuses_a_short_master_password_with_the_expected_code() {
    let harness = Harness::new();

    // The interface branches on these codes, so they are as much a contract as the names.
    assert_eq!(
        harness.error_code("create_vault", json!({ "password": "short" })),
        "weak_password"
    );
}

#[test]
fn refuses_a_wrong_master_password_with_the_expected_code() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));
    harness.ok("lock", json!({}));

    assert_eq!(
        harness.error_code("unlock", json!({ "password": "a different long password" })),
        "unauthentic"
    );
}

#[test]
fn refuses_to_create_a_second_vault() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));

    assert_eq!(
        harness.error_code("create_vault", json!({ "password": MASTER })),
        "vault_exists"
    );
}

#[test]
fn reports_that_there_is_nothing_to_unlock() {
    let harness = Harness::new();

    assert_eq!(
        harness.error_code("unlock", json!({ "password": MASTER })),
        "no_vault"
    );
}

#[test]
fn adds_lists_reveals_updates_and_removes_a_credential() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));

    let id = harness.ok(
        "add_entry",
        json!({ "draft": draft("github.com", "octocat", "hunter2") }),
    );
    let id = id.as_str().expect("an id");

    let listed = harness.ok("list_entries", json!({ "query": null }));
    assert_eq!(listed.as_array().expect("a list").len(), 1);
    assert_eq!(listed[0]["site"], json!("github.com"));

    let revealed = harness.ok("reveal_entry", json!({ "id": id }));
    assert_eq!(revealed["password"], json!("hunter2"));

    harness.ok(
        "update_entry",
        json!({ "id": id, "draft": draft("github.com", "octocat", "rotated") }),
    );
    assert_eq!(
        harness.ok("reveal_entry", json!({ "id": id }))["password"],
        json!("rotated")
    );

    harness.ok("remove_entry", json!({ "id": id }));
    assert!(harness
        .ok("list_entries", json!({ "query": null }))
        .as_array()
        .expect("a list")
        .is_empty());
}

#[test]
fn a_listing_never_carries_a_password() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));
    harness.ok(
        "add_entry",
        json!({ "draft": draft("github.com", "octocat", "hunter2") }),
    );

    let listed = harness.ok("list_entries", json!({ "query": null }));

    // The type makes this impossible in Rust. This asserts it over the wire, where the interface
    // actually receives it.
    assert!(listed[0].get("password").is_none());
    assert!(!listed.to_string().contains("hunter2"));
}

#[test]
fn filters_a_listing_by_query() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));
    harness.ok(
        "add_entry",
        json!({ "draft": draft("github.com", "octocat", "p") }),
    );
    harness.ok(
        "add_entry",
        json!({ "draft": draft("gitlab.com", "tanuki", "p") }),
    );

    let found = harness.ok("list_entries", json!({ "query": "lab" }));

    assert_eq!(found.as_array().expect("a list").len(), 1);
    assert_eq!(found[0]["site"], json!("gitlab.com"));
}

#[test]
fn refuses_every_operation_while_locked() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));
    let id = harness.ok("add_entry", json!({ "draft": draft("a.com", "u", "p") }));
    let id = id.as_str().expect("an id").to_owned();
    harness.ok("lock", json!({}));

    for (command, args) in [
        ("list_entries", json!({ "query": null })),
        ("reveal_entry", json!({ "id": id })),
        ("add_entry", json!({ "draft": draft("b.com", "u", "p") })),
        ("remove_entry", json!({ "id": id })),
    ] {
        assert_eq!(harness.error_code(command, args), "locked", "{command}");
    }
}

#[test]
fn reports_a_missing_credential_with_the_expected_code() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));

    assert_eq!(
        harness.error_code(
            "reveal_entry",
            json!({ "id": "00000000-0000-4000-8000-000000000000" })
        ),
        "not_found"
    );
}

#[test]
fn resets_the_vault_back_to_first_run() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));
    harness.ok(
        "add_entry",
        json!({ "draft": draft("github.com", "octocat", "hunter2") }),
    );

    harness.ok("reset_vault", json!({}));

    // The only way back in when the master password is lost: it recovers nothing and discards
    // everything, leaving the app exactly as a fresh installation.
    assert_eq!(harness.ok("vault_exists", json!({})), json!(false));
    assert_eq!(harness.ok("is_unlocked", json!({})), json!(false));

    harness.ok("create_vault", json!({ "password": MASTER }));
    assert!(harness
        .ok("list_entries", json!({ "query": null }))
        .as_array()
        .expect("a list")
        .is_empty());
}

#[test]
fn changes_the_master_password_over_ipc() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));
    let id = harness.ok(
        "add_entry",
        json!({ "draft": draft("github.com", "octocat", "hunter2") }),
    );
    let id = id.as_str().expect("an id").to_owned();

    // camelCase keys: Tauri converts each snake_case command parameter to camelCase at the JSON
    // boundary, so `current_password` is received as `currentPassword`. This test is what proved
    // that, and the typed IPC layer sends the same shape.
    harness.ok(
        "change_master_password",
        json!({ "currentPassword": MASTER, "newPassword": "a brand new master password" }),
    );

    harness.ok("lock", json!({}));
    // The old password is refused; the new one opens the vault with its credential intact.
    assert_eq!(
        harness.error_code("unlock", json!({ "password": MASTER })),
        "unauthentic"
    );
    harness.ok(
        "unlock",
        json!({ "password": "a brand new master password" }),
    );
    assert_eq!(
        harness.ok("reveal_entry", json!({ "id": id }))["password"],
        json!("hunter2")
    );
}

#[test]
fn refuses_a_password_change_with_a_wrong_current_password() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));

    assert_eq!(
        harness.error_code(
            "change_master_password",
            json!({ "currentPassword": "not the current one", "newPassword": "a brand new master password" })
        ),
        "unauthentic"
    );
}

fn options(length: u64) -> Value {
    json!({
        "length": length,
        "lowercase": true,
        "uppercase": true,
        "digits": true,
        "symbols": true,
        "avoidAmbiguous": false,
    })
}

#[test]
fn generates_a_password_without_the_vault_being_open() {
    let harness = Harness::new();

    // Generating is not a vault operation. Requiring an unlock first would mean no password
    // could be generated while setting one up.
    let result = harness.ok("generate_password", json!({ "options": options(24) }));

    assert_eq!(
        result["password"]
            .as_str()
            .expect("a password")
            .chars()
            .count(),
        24
    );
    assert!(result["entropyBits"].as_f64().expect("entropy") > 100.0);
}

#[test]
fn refuses_generator_options_with_the_expected_codes() {
    let harness = Harness::new();

    assert_eq!(
        harness.error_code("generate_password", json!({ "options": options(4) })),
        "length_out_of_range"
    );

    let mut nothing = options(20);
    for class in ["lowercase", "uppercase", "digits", "symbols"] {
        nothing[class] = json!(false);
    }
    assert_eq!(
        harness.error_code("generate_password", json!({ "options": nothing })),
        "no_character_classes"
    );
}

#[test]
fn reports_a_credential_without_a_site_with_the_expected_code() {
    let harness = Harness::new();
    harness.ok("create_vault", json!({ "password": MASTER }));

    assert_eq!(
        harness.error_code("add_entry", json!({ "draft": draft("   ", "u", "p") })),
        "site_required"
    );
}
