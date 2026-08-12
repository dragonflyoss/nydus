#!/usr/bin/env python3
"""D2 batch: dead-logic + dead-code deletions from the architecture review.

Run from repo root: python3 scripts/refactor_d2.py
Then: cargo fmt --all && cargo test --workspace --all-features
Each item asserts its pattern count and is skipped (reported) on mismatch.
"""
import re

ok, skip = [], []


def sub(path, pat, rep, item, flags=0, expect=1):
    s = open(path).read()
    s2, n = re.subn(pat, rep, s, count=expect, flags=flags)
    if n != expect:
        skip.append(f"{item}(n={n})")
        return
    open(path, "w").write(s2)
    ok.append(item)


# A8c: merge epoch dead logic (root mtime is always 0)
s = open("nydus/src/merge.rs").read()
s2, n1 = re.subn(
    r"let build_time = SystemTime::now\(\)[^;]*;\s*let epoch = inodes\s*\.iter\(\)\s*\.map\(\|inode\| inode\.mtime\)\s*\.min\(\)\s*\.unwrap_or\(build_time\);",
    "// `build_tree` zeroes the root mtime for reproducibility, so the minimum\n    // inode mtime read back from any layer is always 0.\n    let epoch = 0;",
    s,
    flags=re.S,
)
s2, n2 = re.subn(
    r"let epoch = inodes\s*\.iter\(\)\s*\.map\(\|inode\| inode\.mtime\)\s*\.min\(\)\s*\.unwrap_or_else\(\|\| reader\.sb\(\)\.epoch\(\)\);",
    "// See merge_sources_to_bootstrap_bytes: the root mtime is always 0.\n    let epoch = 0;",
    s2,
    flags=re.S,
)
if n1 == 1 and n2 == 1:
    s2 = s2.replace("use std::time::SystemTime;\n", "")
    open("nydus/src/merge.rs", "w").write(s2)
    ok.append("A8c-epoch")
else:
    skip.append(f"A8c-epoch({n1},{n2})")

# pre-existing warning: unused test imports
sub(
    "nydus/src/fanotify/response.rs",
    r"\n *use std::os::fd::\{FromRawFd, OwnedFd\};",
    "",
    "warn-response",
)

# A3: document the intentional (?) per-core vs global trace split
sub(
    "nydus-core/src/storage/cache/local.rs",
    r"(\n *)(if let Some\(recorder\) = self\.trace_recorder\.as_ref\(\) \{)",
    r"\1// Per-core isolation: a cache created through NydusCore records into\1// that core's recorder only, while FUSE-path caches (no recorder) feed\1// the process-global trace behind the apiserver /trace endpoint.\1\2",
    "A3-doc",
)

# dead constants / functions (all grep-verified zero consumers in the audit)
sub(
    "nydus-core/src/metadata/mod.rs",
    r"\n(?:/// [^\n]*\n)*pub const EROFS_I_NLINK_1_BIT[^\n]*\n",
    "\n",
    "nlink1bit",
)

s = open("nydus-core/src/utils/digest.rs").read()
s2, n = re.subn(r"\npub fn sha256_file_region.*?\n\}\n", "\n", s, count=1, flags=re.S)
s2, n2 = re.subn(
    r"\n    #\[test\]\n    fn sha256_file_region_hashes_from_offset.*?\n    \}\n",
    "\n",
    s2,
    count=1,
    flags=re.S,
)
s2 = s2.replace(
    ", sha256_file_range, sha256_file_region,\n    };", ", sha256_file_range,\n    };"
)
if n == 1 and n2 == 1:
    open("nydus-core/src/utils/digest.rs", "w").write(s2)
    ok.append("sha256_file_region")
else:
    skip.append(f"sha256_file_region({n},{n2})")
sub(
    "nydus-core/src/utils/mod.rs",
    r"sha256_file_range, sha256_file_region,",
    "sha256_file_range,",
    "digest-reexport",
)

sub(
    "nydus-core/src/metadata/inode.rs",
    r"\n(?:    /// [^\n]*\n)*    pub fn is_compact\(&self\).*?\n    \}\n",
    "\n",
    "is_compact",
    flags=re.S,
)
sub(
    "nydus-core/src/metadata/inode.rs",
    r"\n(?:    /// [^\n]*\n)*    pub fn mtime_nsec\(&self\).*?\n    \}\n",
    "\n",
    "mtime_nsec",
    flags=re.S,
)
sub(
    "nydus-core/src/metadata/blob_meta.rs",
    r"\n(?:    /// [^\n]*\n)*    pub fn chunk_at\(&self.*?\n    \}\n",
    "\n",
    "chunk_at",
    flags=re.S,
)
sub(
    "nydus-core/src/build/blob_chunk.rs",
    r"\n(?:    /// [^\n]*\n)*    pub fn into_file\(self\).*?\n    \}\n",
    "\n",
    "into_file",
    flags=re.S,
)

s = open("nydus-core/src/build/dir.rs").read()
s2 = re.sub(r"\n *let _ = dirent_area;\n", "\n", s)
if s2 != s:
    open("nydus-core/src/build/dir.rs", "w").write(s2)
    ok.append("dirent_area-discard")
else:
    skip.append("dirent_area-discard")

sub(
    "nydus-core/src/storage/group_map.rs",
    r"\n(?:    /// [^\n]*\n)*    pub fn ready_count\(&self\).*?\n    \}\n",
    "\n",
    "ready_count",
    flags=re.S,
)

s = open("nydus-core/src/lib.rs").read()
s2, n = re.subn(
    r"\n    /// Clear this core's on-demand group trace\.\n    pub fn clear_trace\(&self\) \{\n        self\.trace_recorder\.clear\(\);\n    \}\n",
    "\n",
    s,
    count=1,
)
s2, n2 = re.subn(
    r"\n    /// Return a snapshot of the process-wide nydus metrics.*?\n    pub fn metrics_snapshot\(&self\).*?\n    \}\n",
    "\n",
    s2,
    count=1,
    flags=re.S,
)
if n == 1 and n2 == 1:
    open("nydus-core/src/lib.rs", "w").write(s2)
    ok.append("core-dead-methods")
else:
    skip.append(f"core-dead-methods({n},{n2})")

print("OK:", ok)
print("SKIP:", skip)
