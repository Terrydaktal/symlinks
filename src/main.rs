use clap::Parser;
use glob::Pattern;
use path_clean::PathClean;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use walkdir::WalkDir;

const RED: &str = "\x1b[0;31m";
const GREEN: &str = "\x1b[0;32m";
const YELLOW: &str = "\x1b[1;33m";
const PURPLE: &str = "\x1b[0;35m";
const CYAN: &str = "\x1b[0;36m";
const BOLD: &str = "\x1b[1m";
const NC: &str = "\x1b[0m";

#[derive(Parser, Debug)]
#[command(
    name = "symlinks",
    bin_name = "symlinks",
    about = "Audit and analyze symlinks for a directory",
    disable_help_subcommand = true
)]
struct Cli {
    /// Folder to audit.
    folder: PathBuf,

    /// Where to start scanning for incoming links.
    #[arg(long, default_value = "/")]
    root: PathBuf,

    /// Disable automatic sudo re-exec for incoming scans.
    #[arg(long)]
    no_sudo: bool,

    /// Skip system scan for incoming links.
    #[arg(long)]
    no_system_scan: bool,

    /// Show only incoming links.
    #[arg(long)]
    incoming: bool,

    /// Show only internal links.
    #[arg(long)]
    internal: bool,

    /// Show only external links.
    #[arg(long)]
    external: bool,
}

#[derive(Clone)]
struct LinkRecord {
    link: PathBuf,
    raw: PathBuf,
    resolved: PathBuf,
    broken_now: bool,
    immediate_target_abs: PathBuf,
}

#[derive(Default, Clone)]
struct LsColors {
    link: Option<String>,
    link_target: bool,
    orphan: Option<String>,
    file: Option<String>,
    dir: Option<String>,
    exec: Option<String>,
    patterns: Vec<(Pattern, String)>,
    exact: HashMap<String, String>,
}

impl LsColors {
    fn from_env() -> Self {
        let mut colors = LsColors::default();
        let raw = match std::env::var("LS_COLORS") {
            Ok(v) => v,
            Err(_) => return colors,
        };

        for part in raw.split(':') {
            if part.is_empty() {
                continue;
            }
            let Some((k, v)) = part.split_once('=') else {
                continue;
            };
            if v.is_empty() {
                continue;
            }
            match k {
                "ln" => {
                    if v == "target" {
                        colors.link_target = true;
                        colors.link = None;
                    } else {
                        colors.link = Some(v.to_string());
                    }
                }
                "or" => colors.orphan = Some(v.to_string()),
                "fi" => colors.file = Some(v.to_string()),
                "di" => colors.dir = Some(v.to_string()),
                "ex" => colors.exec = Some(v.to_string()),
                _ => {
                    if k.contains('*') || k.contains('?') || k.contains('[') {
                        if let Ok(pat) = Pattern::new(k) {
                            colors.patterns.push((pat, v.to_string()));
                        }
                    } else {
                        colors.exact.insert(k.to_string(), v.to_string());
                    }
                }
            }
        }

        colors
    }

    fn apply(&self, code: Option<&str>, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        match code {
            Some(c) if !c.is_empty() => format!("\x1b[{c}m{text}{NC}"),
            _ => text.to_string(),
        }
    }

    fn matched_name_code(&self, name: &str) -> Option<String> {
        let mut out = self.exact.get(name).cloned();
        for (pat, code) in &self.patterns {
            if pat.matches(name) {
                out = Some(code.clone());
            }
        }
        out
    }

    fn target_code(&self, resolved: &Path, broken_now: bool) -> Option<String> {
        if broken_now {
            return self.orphan.clone().or(self.link.clone());
        }

        let meta = match fs::metadata(resolved) {
            Ok(v) => v,
            Err(_) => return self.file.clone(),
        };

        if meta.is_dir() {
            return self.dir.clone();
        }

        if let Some(name) = resolved.file_name().and_then(|x| x.to_str()) {
            if let Some(c) = self.matched_name_code(name) {
                return Some(c);
            }
        }

        #[cfg(unix)]
        {
            if meta.permissions().mode() & 0o111 != 0 {
                return self.exec.clone().or(self.file.clone());
            }
        }

        self.file.clone()
    }

    fn link_code(&self, resolved: &Path, broken_now: bool) -> Option<String> {
        if broken_now {
            return self.orphan.clone().or(self.link.clone());
        }
        if self.link_target {
            return self.target_code(resolved, false);
        }
        self.link.clone()
    }
}

fn abs_clean(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.clean();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path).clean(),
        Err(_) => PathBuf::from("/").join(path).clean(),
    }
}

fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(p) = fs::canonicalize(path) {
        return p;
    }

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            if let Ok(raw) = fs::read_link(path) {
                let parent = path.parent().unwrap_or(Path::new("/"));
                let immediate = if raw.is_absolute() {
                    raw
                } else {
                    parent.join(raw)
                };
                if let Ok(p) = fs::canonicalize(&immediate) {
                    return p;
                }
                return abs_clean(&immediate);
            }
        }
    }

    abs_clean(path)
}

fn make_markers(broken_now: bool, broken_if_moved: bool) -> String {
    let mut out = String::new();
    if broken_now {
        out.push_str(&format!(" {BOLD}{RED}[BROKEN NOW]{NC}"));
    }
    if broken_if_moved {
        out.push_str(&format!(" {BOLD}{RED}[BROKEN IF MOVED]{NC}"));
    }
    out
}

fn resolved_suffix(raw: &Path, resolved: &Path) -> String {
    if raw.is_absolute() {
        String::new()
    } else {
        format!(" ({CYAN}resolved: {}{NC})", resolved.display())
    }
}

fn is_inside(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn is_excluded_dir_name(name: &str) -> bool {
    matches!(
        name,
        "proc"
            | "sys"
            | "dev"
            | "run"
            | "mnt"
            | "tmp"
            | ".git"
            | ".cache"
            | "node_modules"
    )
}

fn collect_internal_external(folder_abs: &Path, ls_colors: &LsColors) -> (Vec<String>, Vec<String>) {
    let mut internal_lines = Vec::new();
    let mut external_lines = Vec::new();

    for entry_result in WalkDir::new(folder_abs).follow_links(false) {
        let entry = match entry_result {
            Ok(v) => v,
            Err(_) => continue,
        };

        if !entry.file_type().is_symlink() {
            continue;
        }

        let link = entry.path().to_path_buf();
        let raw = match fs::read_link(&link) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let resolved = resolve_path(&link);
        let broken_now = fs::metadata(&link).is_err();
        let parent = link.parent().unwrap_or(Path::new("/"));
        let immediate_target_abs = if raw.is_absolute() {
            raw.clone()
        } else {
            abs_clean(&parent.join(&raw))
        };

        let rec = LinkRecord {
            link,
            raw,
            resolved,
            broken_now,
            immediate_target_abs,
        };

        if is_inside(&rec.resolved, folder_abs) {
            let broken_if_moved = rec.raw.is_absolute();
            let markers = make_markers(rec.broken_now, broken_if_moved);
            let resolved = resolved_suffix(&rec.raw, &rec.resolved);
            let link_disp = ls_colors.apply(
                ls_colors.link_code(&rec.resolved, rec.broken_now).as_deref(),
                rec.link.display().to_string(),
            );
            let raw_disp = ls_colors.apply(
                ls_colors.target_code(&rec.resolved, rec.broken_now).as_deref(),
                rec.raw.display().to_string(),
            );
            internal_lines.push(format!(
                "{} -> {}{}{}",
                link_disp,
                raw_disp,
                resolved,
                markers
            ));
        } else {
            let mut broken_if_moved = false;
            if !rec.raw.is_absolute() && !is_inside(&rec.immediate_target_abs, folder_abs) {
                broken_if_moved = true;
            }
            let markers = make_markers(rec.broken_now, broken_if_moved);
            let resolved = resolved_suffix(&rec.raw, &rec.resolved);
            let link_disp = ls_colors.apply(
                ls_colors.link_code(&rec.resolved, rec.broken_now).as_deref(),
                rec.link.display().to_string(),
            );
            let raw_disp = ls_colors.apply(
                ls_colors.target_code(&rec.resolved, rec.broken_now).as_deref(),
                rec.raw.display().to_string(),
            );
            external_lines.push(format!(
                "{} -> {}{}{}",
                link_disp,
                raw_disp,
                resolved,
                markers
            ));
        }
    }

    (internal_lines, external_lines)
}

fn scan_incoming(folder_abs: &Path, scan_root_abs: &Path, ls_colors: &LsColors) {
    println!(
        "{BOLD}{PURPLE}== 1: Incoming Symlinks (Outside -> {}) =={NC}",
        folder_abs.display()
    );
    println!(
        "{CYAN}(These are sensitive to moving {}; [BROKEN NOW] means the target is missing today){NC}",
        folder_abs.display()
    );

    let mut iter = WalkDir::new(scan_root_abs).follow_links(false).into_iter();
    while let Some(entry_result) = iter.next() {
        let entry = match entry_result {
            Ok(v) => v,
            Err(_) => continue,
        };

        if entry.file_type().is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                if is_excluded_dir_name(name) {
                    iter.skip_current_dir();
                    continue;
                }
            }
        }

        if !entry.file_type().is_symlink() {
            continue;
        }

        let link = entry.path();
        if is_inside(link, folder_abs) {
            continue;
        }

        let resolved = resolve_path(link);
        if !is_inside(&resolved, folder_abs) {
            continue;
        }

        let raw = match fs::read_link(link) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let broken_now = fs::metadata(link).is_err();
        let markers = make_markers(broken_now, true);
        let resolved_suffix = resolved_suffix(&raw, &resolved);
        let link_disp = ls_colors.apply(
            ls_colors.link_code(&resolved, broken_now).as_deref(),
            link.display().to_string(),
        );
        let raw_disp = ls_colors.apply(
            ls_colors.target_code(&resolved, broken_now).as_deref(),
            raw.display().to_string(),
        );
        println!(
            "{} -> {}{}{}",
            link_disp,
            raw_disp,
            resolved_suffix,
            markers
        );
    }

    println!();
}

fn is_root_user() -> bool {
    match Command::new("id").arg("-u").output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim() == "0",
        Err(_) => false,
    }
}

fn maybe_rerun_with_sudo(cli: &Cli, do_incoming: bool) -> bool {
    if !do_incoming || cli.no_system_scan || cli.no_sudo || is_root_user() {
        return false;
    }
    if std::env::var("SYMLINKS_RS_SUDO_REEXEC").ok().as_deref() == Some("1") {
        return false;
    }

    let exe = match std::env::current_exe() {
        Ok(v) => v,
        Err(_) => return false,
    };

    let mut cmd = Command::new("sudo");
    cmd.arg("--preserve-env=LS_COLORS,TERM,COLORTERM");
    cmd.env("SYMLINKS_RS_SUDO_REEXEC", "1");
    cmd.arg(exe);
    for arg in std::env::args().skip(1) {
        cmd.arg(arg);
    }

    match cmd.status() {
        Ok(status) => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(_) => false,
    }
}

fn main() {
    let cli = Cli::parse();
    let ls_colors = LsColors::from_env();

    let section_selected = cli.incoming || cli.internal || cli.external;
    let do_incoming = if section_selected { cli.incoming } else { true };
    let do_internal = if section_selected { cli.internal } else { true };
    let do_external = if section_selected { cli.external } else { true };

    if maybe_rerun_with_sudo(&cli, do_incoming) {
        return;
    }

    let folder_abs = resolve_path(&cli.folder);
    if !folder_abs.is_dir() {
        eprintln!(
            "{RED}Error: folder does not exist or is not a directory: {}{NC}",
            folder_abs.display()
        );
        std::process::exit(1);
    }

    let scan_root_abs = resolve_path(&cli.root);
    if do_incoming && !cli.no_system_scan {
        if cli.no_sudo {
            // Compatibility flag retained from shell version; scanning remains best-effort.
        }
        scan_incoming(&folder_abs, &scan_root_abs, &ls_colors);
    }

    if do_internal || do_external {
        let (internal_lines, external_lines) = collect_internal_external(&folder_abs, &ls_colors);

        if do_internal {
            println!(
                "{BOLD}{GREEN}== 2: Internal Symlinks ({} -> {}) =={NC}",
                folder_abs.display(),
                folder_abs.display()
            );
            println!(
                "{CYAN}(Absolute internal links break if moved; [BROKEN NOW] means target missing today){NC}"
            );
            if internal_lines.is_empty() {
                println!("{YELLOW}(none){NC}");
            } else {
                for line in internal_lines {
                    println!("{line}");
                }
            }
            println!();
        }

        if do_external {
            println!(
                "{BOLD}{RED}== 3: External Symlinks ({} -> Outside) =={NC}",
                folder_abs.display()
            );
            println!(
                "{CYAN}(Relative external links may break if moved; [BROKEN NOW] means target missing today){NC}"
            );
            if external_lines.is_empty() {
                println!("{YELLOW}(none){NC}");
            } else {
                for line in external_lines {
                    println!("{line}");
                }
            }
        }
    }
}
