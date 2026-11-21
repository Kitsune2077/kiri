//! `~/.kiri/daemon.json`: Kiri's own daemon.json, with Docker's key names,
//! so a setup copied from Docker's file works unchanged. Kiri reads the
//! registry keys (`insecure-registries`, `registry-mirrors`; see
//! kiri_image::config) and keeps every other key as it finds it. Docker
//! Desktop's daemon.json is never read or written.
//!
//! The file is the daemon's, because pulls, pushes and logins happen here;
//! Settings → Registries and `kiri registry` change it through the API
//! (`GET`/`POST /kiri/registries`). An edit by hand applies at the next
//! pull, push or login, without a restart: the file is read again when it
//! changes (its size or time), and otherwise not at all.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use kiri_image::{Insecure, Mirror, RegistryConfig};
use serde_json::{Map, Value, json};

pub const INSECURE: &str = "insecure-registries";
pub const MIRRORS: &str = "registry-mirrors";

/// Enough mirrors to fail over a few times, few enough that a pull does not
/// spend its time asking one dead address after another.
const MAX_MIRRORS: usize = 16;
/// More insecure hosts than anyone lists.
const MAX_INSECURE: usize = 256;

pub fn path() -> Option<PathBuf> {
    super::state_dir().ok().map(|d| d.join("daemon.json"))
}

/// The file's registry settings and what was wrong with it, as last read.
#[derive(Default)]
struct Read {
    stamp: Option<(SystemTime, u64)>,
    config: Arc<RegistryConfig>,
    problems: Vec<String>,
}

static READ: Mutex<Option<Read>> = Mutex::new(None);

/// What the file says now. A stat per call; read and parsed again only when
/// it changed. No file, or one Kiri can't read, is no settings.
pub fn current() -> Arc<RegistryConfig> {
    with_current(|r| r.config.clone())
}

fn with_current<T>(f: impl FnOnce(&Read) -> T) -> T {
    let path = path();
    let stamp = path.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()));
    let mut slot = READ.lock().unwrap_or_else(|e| e.into_inner());
    if slot.as_ref().is_none_or(|r| r.stamp != stamp) {
        let (config, problems) = match (&path, stamp) {
            (Some(p), Some(_)) => match std::fs::read(p) {
                Ok(bytes) => parse(&bytes),
                Err(e) => (RegistryConfig::default(), vec![format!("{} could not be read: {e}", p.display())]),
            },
            _ => (RegistryConfig::default(), Vec::new()),
        };
        for p in &problems {
            crate::diag::warn!("daemon.json", problem = p.as_str());
        }
        *slot = Some(Read { stamp, config: Arc::new(config), problems });
    }
    f(slot.as_ref().expect("just set"))
}

/// The registry settings in a daemon.json, and what in it was left out and
/// why. As Docker, a key of the wrong kind is an error; unlike Docker, the
/// daemon keeps running with the entries it could read and says what it
/// skipped (Settings and `kiri registry` show it).
fn parse(bytes: &[u8]) -> (RegistryConfig, Vec<String>) {
    let mut problems = Vec::new();
    let v: Value = match serde_json::from_slice(bytes) {
        Ok(v @ Value::Object(_)) => v,
        Ok(_) => return (RegistryConfig::default(), vec!["daemon.json is not a JSON object".into()]),
        Err(e) => return (RegistryConfig::default(), vec![format!("daemon.json is not valid JSON: {e}")]),
    };
    let insecure = strings(&v, INSECURE, &mut problems).into_iter().filter_map(|s| Insecure::parse(&s).map_err(|e| problems.push(format!("{INSECURE}: {e}"))).ok()).collect();
    let mirrors = strings(&v, MIRRORS, &mut problems).into_iter().filter_map(|s| Mirror::parse(&s).map_err(|e| problems.push(format!("{MIRRORS}: {e}"))).ok()).collect();
    (RegistryConfig { insecure, mirrors }, problems)
}

fn strings(v: &Value, key: &str, problems: &mut Vec<String>) -> Vec<String> {
    match &v[key] {
        Value::Null => Vec::new(),
        Value::Array(a) => a
            .iter()
            .filter_map(|e| match e.as_str() {
                Some(s) => Some(s.to_owned()),
                None => {
                    problems.push(format!("{key}: {e} is not a string"));
                    None
                }
            })
            .collect(),
        other => {
            problems.push(format!("{key} must be a list, not {other}"));
            Vec::new()
        }
    }
}

/// What Settings and `kiri registry` show: both lists as the file keeps
/// them, the file's path, and what in it was skipped.
pub fn report() -> Value {
    with_current(|r| {
        json!({
            INSECURE: r.config.insecure.iter().map(Insecure::as_string).collect::<Vec<_>>(),
            MIRRORS: r.config.mirrors.iter().map(Mirror::as_url).collect::<Vec<_>>(),
            "path": path().map(|p| p.display().to_string()).unwrap_or_default(),
            "problems": r.problems,
        })
    })
}

/// Docker's `RegistryConfig` in `GET /info`, which `docker info` prints as
/// "Insecure Registries" and "Registry Mirrors": loopback is insecure as on
/// Docker, and so is every host and network daemon.json lists.
pub fn info() -> Value {
    let c = current();
    let mut cidrs = vec!["::1/128".to_owned(), "127.0.0.0/8".to_owned()];
    let mut indexes = Map::new();
    let mirrors: Vec<String> = c.mirrors.iter().map(|m| format!("{}/", m.as_url())).collect();
    indexes.insert("docker.io".into(), json!({"Name": "docker.io", "Mirrors": mirrors, "Secure": true, "Official": true}));
    for e in &c.insecure {
        match e {
            Insecure::Net(..) => cidrs.push(e.as_string()),
            Insecure::Host(h) => {
                indexes.insert(h.clone(), json!({"Name": h, "Mirrors": [], "Secure": false, "Official": false}));
            }
        }
    }
    json!({"InsecureRegistryCIDRs": cidrs, "IndexConfigs": indexes, "Mirrors": mirrors})
}

/// Saves the lists in `body` (`insecure-registries`, `registry-mirrors`;
/// a key left out keeps what the file has), each entry checked and written
/// as it will be read, duplicates dropped. Every other key in the file is
/// kept. A file that isn't a JSON object is not overwritten: the person
/// has to fix it, so nothing of theirs is lost. Returns the new report.
pub fn set(body: &Value) -> Result<Value, String> {
    let path = path().ok_or_else(|| "HOME is not set".to_owned())?;
    let mut file = match std::fs::read(&path) {
        Ok(b) if b.iter().all(u8::is_ascii_whitespace) => Map::new(),
        Ok(b) => match serde_json::from_slice::<Value>(&b) {
            Ok(Value::Object(m)) => m,
            _ => return Err(format!("{} is not a JSON object; fix it or remove it, then save again", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Map::new(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut given = false;
    if let Some(v) = body.get(INSECURE) {
        file.insert(INSECURE.into(), json!(normalize(v, INSECURE, MAX_INSECURE, |s| Insecure::parse(s).map(|e| e.as_string()))?));
        given = true;
    }
    if let Some(v) = body.get(MIRRORS) {
        file.insert(MIRRORS.into(), json!(normalize(v, MIRRORS, MAX_MIRRORS, |s| Mirror::parse(s).map(|m| m.as_url()))?));
        given = true;
    }
    if !given {
        return Err(format!("nothing to save: send {INSECURE} or {MIRRORS}"));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut text = serde_json::to_string_pretty(&Value::Object(file)).map_err(|e| e.to_string())?;
    text.push('\n');
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(report())
}

/// A list from Settings or the CLI: strings, each one checked and written
/// the way it reads back, in order, once each.
fn normalize(v: &Value, key: &str, max: usize, check: impl Fn(&str) -> Result<String, String>) -> Result<Vec<String>, String> {
    let given = v.as_array().ok_or_else(|| format!("{key} must be a list"))?;
    if given.len() > max {
        return Err(format!("{key}: at most {max}"));
    }
    let mut out: Vec<String> = Vec::new();
    for e in given {
        let s = e.as_str().ok_or_else(|| format!("{key}: {e} is not a string"))?;
        let n = check(s).map_err(|e| format!("{key}: {e}"))?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dockers_keys_are_read() {
        let (c, problems) = parse(br#"{"insecure-registries": ["registry.lan:5000", "http://10.0.0.0/8"], "registry-mirrors": ["https://mirror.example.com/"], "debug": true}"#);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(c.is_insecure("registry.lan:5000"));
        assert!(c.is_insecure("10.1.2.3:5000"));
        assert_eq!(c.mirrors.iter().map(Mirror::as_url).collect::<Vec<_>>(), ["https://mirror.example.com"]);
    }

    #[test]
    fn what_cant_be_read_is_skipped_and_said() {
        let (c, problems) = parse(br#"{"insecure-registries": ["ok.lan:5000", "0.0.0.0/0", 7], "registry-mirrors": "https://m.example.com"}"#);
        assert!(c.is_insecure("ok.lan:5000"));
        assert!(c.mirrors.is_empty());
        assert_eq!(problems.len(), 3, "{problems:?}");
        let (c, problems) = parse(b"{not json");
        assert_eq!(c, RegistryConfig::default());
        assert!(problems[0].contains("not valid JSON"));
        assert!(parse(b"[]").1[0].contains("not a JSON object"));
    }

    #[test]
    fn lists_are_checked_and_written_as_they_read() {
        let insecure = normalize(&json!(["Registry.LAN:5000", "http://registry.lan:5000", "10.1.0.0/16"]), INSECURE, 8, |s| Insecure::parse(s).map(|e| e.as_string())).unwrap();
        assert_eq!(insecure, ["registry.lan:5000", "10.1.0.0/16"]);
        assert!(normalize(&json!(["docker.io"]), INSECURE, 8, |s| Insecure::parse(s).map(|e| e.as_string())).is_err());
        assert!(normalize(&json!("registry.lan"), INSECURE, 8, |s| Insecure::parse(s).map(|e| e.as_string())).is_err());
        assert!(normalize(&json!(["a.lan", "b.lan"]), INSECURE, 1, |s| Insecure::parse(s).map(|e| e.as_string())).is_err());
        let mirrors = normalize(&json!(["mirror.example.com", "https://mirror.example.com/", "http://mirror.lan:5000"]), MIRRORS, 8, |s| Mirror::parse(s).map(|m| m.as_url())).unwrap();
        assert_eq!(mirrors, ["https://mirror.example.com", "http://mirror.lan:5000"]);
    }
}
