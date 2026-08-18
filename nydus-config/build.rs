use std::path::Path;
use std::process::Command;

/// Represents the git commit information.
struct Commit {
    /// The short hash of the commit.
    short_hash: String,

    /// The date of the commit.
    date: String,
}

/// Returns the git commit information.
fn get_commit_from_git() -> Option<Commit> {
    if !Path::new("../.git").exists() {
        return None;
    }

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
    // Get the commit information from git.
    if let Some(commit) = get_commit_from_git() {
        // Set the environment variables for the git commit short.
        println!(
            "cargo:rustc-env=GIT_COMMIT_SHORT_HASH={}",
            commit.short_hash
        );

        // Set the environment variables for the git commit date.
        println!("cargo:rustc-env=GIT_COMMIT_DATE={}", commit.date);
    }
}
