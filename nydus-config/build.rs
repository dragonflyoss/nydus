use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Represents the git commit information.
struct Commit {
    /// The short hash of the commit.
    short_hash: String,

    /// The date of the commit.
    date: String,
}

/// Resolves `path` inside the git directory to an absolute location.
///
/// `git rev-parse --git-path` follows `gitdir:` files of submodules and
/// worktrees, and maps shared entries such as `refs/` and `packed-refs` to the
/// common directory while `HEAD` stays per-worktree.
fn git_path(path: &str) -> Option<PathBuf> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--git-path")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    if path.is_absolute() {
        Some(path)
    } else {
        Some(env::current_dir().ok()?.join(path))
    }
}

/// Tells cargo to re-run this script whenever the checked-out commit changes,
/// so the embedded version does not go stale between builds.
fn emit_git_rerun_triggers() {
    // `refs/heads` is declared as a whole directory so a loose ref written after
    // `git gc` packed the branch is still noticed; `reftable` covers repositories
    // using that ref backend. Missing paths must not be declared because cargo
    // treats them as always stale and would re-run on every build.
    for path in ["HEAD", "refs/heads", "packed-refs", "reftable"] {
        if let Some(path) = git_path(path).filter(|path| path.exists()) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

/// Returns the commit the build environment names with `GIT_COMMIT_SHORT_HASH`
/// and `GIT_COMMIT_DATE`.
///
/// A build of the source without its `.git` directory, as in an image build
/// whose context leaves it out, names the commit this way. It wins over git, as
/// moby's `DOCKER_GITCOMMIT` and Kubernetes's `KUBE_GIT_COMMIT` do.
fn get_commit_from_env() -> Option<Commit> {
    let var = |name: &str| {
        println!("cargo:rerun-if-env-changed={name}");
        env::var(name).ok().filter(|value| !value.is_empty())
    };

    let (short_hash, date) = (var("GIT_COMMIT_SHORT_HASH"), var("GIT_COMMIT_DATE"));
    Some(Commit {
        short_hash: short_hash?,
        date: date?,
    })
}

/// Returns the git commit information.
fn get_commit_from_git() -> Option<Commit> {
    // Only trust git when the crate sits inside the nydus source tree; a
    // vendored copy inside some other repository must not report that
    // repository's commit.
    if !Path::new("../.git").exists() {
        return None;
    }
    emit_git_rerun_triggers();

    let output = match Command::new("git")
        .arg("log")
        .arg("-1")
        .arg("--date=short")
        .arg("--format=%h %cd")
        .arg("--abbrev=9")
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return None,
    };

    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut parts = stdout.split_whitespace().map(|s| s.to_string());

    Some(Commit {
        short_hash: parts.next()?,
        date: parts.next()?,
    })
}

fn main() {
    // Get the commit information from the environment, then from git.
    if let Some(commit) = get_commit_from_env().or_else(get_commit_from_git) {
        // Set the environment variables for the git commit short.
        println!(
            "cargo:rustc-env=GIT_COMMIT_SHORT_HASH={}",
            commit.short_hash
        );

        // Set the environment variables for the git commit date.
        println!("cargo:rustc-env=GIT_COMMIT_DATE={}", commit.date);
    }
}
