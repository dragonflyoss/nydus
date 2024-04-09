// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, io};

use clap::*;
use http_range::HttpRange;
use lazy_static::lazy_static;
use nix::sys::uio;
use rocket::fs::{FileServer, NamedFile};
use rocket::futures::lock::{Mutex, MutexGuard};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Outcome};
use rocket::response::{self, stream::ReaderStream, Responder};
use rocket::*;

lazy_static! {
    static ref BLOB_BACKEND: Mutex<BlobBackend> = Mutex::new(BlobBackend {
        root: PathBuf::default(),
        blobs: HashMap::new()
    });
}

async fn blob_backend_mut() -> MutexGuard<'static, BlobBackend> {
    BLOB_BACKEND.lock().await
}

async fn init_blob_backend(root: &Path) {
    let mut b = BlobBackend {
        root: root.to_path_buf(),
        blobs: HashMap::new(),
    };

    b.populate_blobs_map();
    *BLOB_BACKEND.lock().await = b;
}

#[derive(Debug)]
struct BlobBackend {
    root: PathBuf,
    blobs: HashMap<String, Arc<fs::File>>,
}

impl BlobBackend {
    fn populate_blobs_map(&mut self) {
        for entry in self
            .root
            .read_dir()
            .expect("read blobsdir failed")
            .flatten()
        {
            let filepath = entry.path();
            if filepath.is_file() {
                // Collaborating system should put files with valid name which
                // can also be converted to UTF-8
                let digest = filepath.file_name().unwrap().to_string_lossy();
                if self.blobs.contains_key(digest.as_ref()) {
                    continue;
                }

                match fs::File::open(&filepath) {
                    Ok(f) => {
                        self.blobs.insert(digest.into_owned(), Arc::new(f));
                    }
                    Err(e) => warn!("failed to open file {}, {}", digest, e),
                }
            } else {
                debug!("%s: Not regular file");
            }
        }
    }
}

#[derive(Debug)]
struct HeaderData {
    _host: String,
    range: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for HeaderData {
    type Error = Status;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<HeaderData, Self::Error> {
        let headers = req.headers();
        let _host = headers.get_one("Host").unwrap_or_default().to_string();
        let range = headers.get_one("Range").unwrap_or_default().to_string();

        Outcome::Success(HeaderData { _host, range })
    }
}

#[rocket::head("/<_namespace>/<_repo>/blobs/<digest>")]
async fn check(
    _namespace: PathBuf,
    _repo: PathBuf,
    digest: String,
) -> Result<Option<FileStream>, Status> {
    if !digest.starts_with("sha256:") {
        return Err(Status::BadRequest);
    }

    // Trim "sha256:" prefix
    let dis = &digest[7..];
    let backend = blob_backend_mut();
    let path = backend.await.root.join(&dis);

    NamedFile::open(path)
        .await
        .map_err(|_e| Status::NotFound)
        .map(|nf| Some(FileStream(nf, dis.to_string())))
}

/* fetch blob response
 * NamedFile: blob data
 * String: Docker-Content-Digest
 */
struct FileStream(NamedFile, String);

impl<'r> Responder<'r, 'static> for FileStream {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        let res = self.0.respond_to(req)?;
        Response::build_from(res)
            .raw_header("Docker-Content-Digest", self.1)
            .raw_header("Content-Type", "application/octet-stream")
            .ok()
    }
}

/* fetch blob part response(stream)
 * path: path of blob
 * dis: Docker-Content-Digest
 * start & end: "Content-Range: bytes <start>-<end>/<size>"
 */
struct RangeStream {
    dis: String,
    start: u64,
    len: u64,
    file: Arc<fs::File>,
}

impl RangeStream {
    fn get_rangestr(&self) -> String {
        let endpos = self.start + self.len - 1;
        format!("bytes {}-{}/{}", self.start, endpos, self.len)
    }
}

impl<'r> Responder<'r, 'static> for RangeStream {
    fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
        const BUFSIZE: usize = 4096;
        let mut buf = vec![0; BUFSIZE];
        let mut read = 0u64;
        let startpos = self.start as i64;
        let size = self.len;
        let file = self.file.clone();

        Response::build()
            .streamed_body(ReaderStream! {
                while read < size {
                    match uio::pread(file.as_ref(), &mut buf, startpos + read as i64) {
                        Ok(mut n) => {
                            n = std::cmp::min(n, (size - read) as usize);
                            read += n as u64;
                            if n == 0 {
                                break;
                            } else if n < BUFSIZE {
                                yield io::Cursor::new(buf[0..n].to_vec());
                            } else {
                                yield io::Cursor::new(buf.clone());
                            }
                        }
                        Err(err) => {
                            eprintln!("ReaderStream Error: {}", err);
                            break;
                        }
                    }
                }
            })
            .raw_header("Content-Range", self.get_rangestr())
            .raw_header("Docker-Content-Digest", self.dis)
            .raw_header("Content-Type", "application/octet-stream")
            .ok()
    }
}

#[derive(Responder)]
enum StoredData {
    AllFile(FileStream),
    Range(RangeStream),
}

#[get("/<_namespace>/<_repo>/blobs/<digest>")]
async fn fetch(
    _namespace: PathBuf,
    _repo: PathBuf,
    digest: String,
    header_data: HeaderData,
) -> Result<StoredData, Status> {
    if !digest.starts_with("sha256:") {
        return Err(Status::BadRequest);
    }

    // Trim "sha256:" prefix
    let dis = &digest[7..];

    //if no range in Request header,return fetch blob response
    if header_data.range.is_empty() {
        let filepath = blob_backend_mut().await.root.join(&dis);
        NamedFile::open(filepath)
            .await
            .map_err(|_e| Status::NotFound)
            .map(|nf| StoredData::AllFile(FileStream(nf, dis.to_string())))
    } else {
        let mut guard = blob_backend_mut().await;
        let blob_file = if let Some(f) = guard.blobs.get(dis) {
            f.clone()
        } else {
            trace!("Blob object not found: {}", dis);
            // Re-populate blobs map by `readdir()` again to scan if files are newly added.
            guard.populate_blobs_map();
            trace!("re-populating to search blob {}", dis);
            guard.blobs.get(dis).cloned().ok_or_else(|| {
                error!("Blob {} not found finally!", dis);
                Status::NotFound
            })?
        };
        drop(guard);

        let metadata = match blob_file.metadata() {
            Ok(meta) => meta,
            Err(e) => {
                eprintln!("Get file metadata failed! Error: {}", e);
                return Err(Status::InternalServerError);
            }
        };

        let ranges = match HttpRange::parse(&header_data.range, metadata.len()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("HttpRange parse failed! Error: {:#?}", e);
                return Err(Status::RangeNotSatisfiable);
            }
        };
        let start_pos = ranges[0].start as u64;
        let size = ranges[0].length;

        Ok(StoredData::Range(RangeStream {
            dis: dis.to_string(),
            len: size,
            start: start_pos,
            file: blob_file,
        }))
    }
}

#[rocket::main]
async fn main() {
    let cmd = Command::new("nydus-backend-proxy")
        .author(env!("CARGO_PKG_AUTHORS"))
        .version(env!("CARGO_PKG_VERSION"))
        .about("A simple HTTP server to provide a fake container registry for nydusd.")
        .arg(
            Arg::new("blobsdir")
                .short('b')
                .long("blobsdir")
                .required(true)
                .help("path to directory hosting nydus blob files"),
        )
        .help_template(
            "\
{before-help}{name} {version}
{author-with-newline}{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
        ",
        )
        .get_matches();
    // Safe to unwrap() because `blobsdir` takes a value.
    let path = cmd
        .get_one::<String>("blobsdir")
        .expect("required argument");

    init_blob_backend(Path::new(path)).await;

    if let Err(e) = rocket::build()
        .mount("/", rocket::routes![check, fetch])
        .mount("/", FileServer::from(&path))
        .launch()
        .await
    {
        error!("Rocket failed to launch, {:#?}", e);
        std::process::exit(-1);
    }
}
