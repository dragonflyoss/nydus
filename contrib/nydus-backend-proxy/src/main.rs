#[macro_use]
extern crate rocket;
#[macro_use]
extern crate lazy_static;
#[macro_use(crate_authors, crate_version)]
extern crate clap;

use std::collections::HashMap;
use std::env;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::path::{Path, PathBuf};
use std::{ffi, fs, io};

use clap::{App, Arg};
use nix::sys::uio;

use http_range::HttpRange;

use rocket::fs::{FileServer, NamedFile};
use rocket::futures::lock::{Mutex, MutexGuard};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Outcome};
use rocket::response::{self, stream::ReaderStream, Responder};
use rocket::Request;
use rocket::Response;

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
    blobs: HashMap<ffi::OsString, fs::File>,
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
                let digest = filepath.file_name().unwrap();

                if self.blobs.contains_key(digest) {
                    continue;
                }

                let std_file = fs::File::open(&filepath).unwrap();
                self.blobs.insert(digest.to_os_string(), std_file);
            } else {
                warn!("%s: Not regular file");
            }
        }
    }
}

#[derive(Debug)]
pub struct HeaderData {
    _host: String,
    range: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for HeaderData {
    type Error = Status;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<HeaderData, Self::Error> {
        let host = match req.headers().get_one("Host") {
            Some(h) => h.to_string(),
            None => "".to_string(),
        };
        let rangestr = match req.headers().get_one("Range") {
            Some(h) => h.to_string(),
            None => "".to_string(),
        };
        Outcome::Success(HeaderData {
            _host: host,
            range: rangestr,
        })
    }
}

#[rocket::head("/<_namespace>/<_repo>/blobs/<digest>")]
pub async fn check(
    _namespace: PathBuf,
    _repo: PathBuf,
    digest: String,
) -> Result<Option<FileStream>, Status> {
    let dis = &digest[7..];
    let blobbackend = blob_backend_mut();
    let path = blobbackend.await.root.join(&dis);
    Ok(NamedFile::open(path)
        .await
        .ok()
        .map(|nf| FileStream(nf, dis.to_string())))
}

/* fetch blob response
 * NamedFile: blob data
 * String: Docker-Content-Digest
 */
pub struct FileStream(NamedFile, String);

impl<'r> Responder<'r, 'static> for FileStream {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        Response::build_from(self.0.respond_to(req)?)
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
pub struct RangeStream {
    dis: String,
    start: u64,
    len: u64,
    fd: RawFd,
}

impl RangeStream {
    fn get_rangestr(&self) -> String {
        let endpos = self.start + self.len - 1;
        format!("bytes {}-{}/{}", self.start, endpos, self.len)
    }
}

impl<'r> Responder<'r, 'static> for RangeStream {
    fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
        let rangestring = self.get_rangestr();
        let size = self.len;
        const BUFSIZE: usize = 4096;
        let mut buf = vec![0; BUFSIZE];
        let mut read = 0;
        let startpos = self.start as i64;
        let raw_fd = self.fd;
        Response::build()
            .streamed_body(ReaderStream! {
                while read < size {
                    let unread = (size - read) as usize;
                    let allbuf: &mut [u8] = &mut buf[..];
                    match uio::pread(raw_fd, allbuf, startpos + read as i64) {
                        Ok(n) => {
                            if n == 0 {
                                break;
                            }
                            read += n as u64;
                            if unread < BUFSIZE {
                                let part = &allbuf[0..unread];
                                yield io::Cursor::new(part.to_vec());
                            } else {
                                yield io::Cursor::new(allbuf.to_vec());
                            }
                        }
                        Err(err) => {
                            eprintln!("ReaderStream Error: {}", err);
                            break;
                        }
                    }
                }
            })
            .raw_header("Docker-Content-Digest", self.dis)
            .raw_header("Content-Type", "application/octet-stream")
            .raw_header("Content-Range", rangestring)
            .ok()
    }
}

#[derive(Responder)]
pub enum StoredData {
    AllFile(Option<FileStream>),
    Range(RangeStream),
}

#[get("/<_namespace>/<_repo>/blobs/<digest>")]
pub async fn fetch(
    _namespace: PathBuf,
    _repo: PathBuf,
    digest: String,
    headerdata: HeaderData,
) -> Result<StoredData, Status> {
    let dis = &digest[7..];
    let blobbackend = blob_backend_mut();
    //if no range in Request header,return fetch blob response
    if headerdata.range.is_empty() {
        let filepath = blobbackend.await.root.join(&dis);
        return Ok(StoredData::AllFile(
            NamedFile::open(filepath)
                .await
                .ok()
                .map(|nf| FileStream(nf, dis.to_string())),
        ));
    } else {
        let blobs = &mut blobbackend.await.blobs;
        let blobfd = match blobs.get(&ffi::OsString::from(&dis)) {
            Some(fd) => fd,
            None => {
                return Err(Status::NotFound);
            }
        };
        let metadata = match blobfd.metadata() {
            Ok(meta) => meta,
            Err(_err) => {
                eprintln!("Get file metadata failed! Error: {}", _err);
                return Err(Status::InternalServerError);
            }
        };
        let ranges = match HttpRange::parse(&headerdata.range, metadata.len()) {
            Ok(r) => r,
            Err(_err) => {
                eprintln!("HttpRange parse failed! Error: {:#?}", _err);
                return Err(Status::RangeNotSatisfiable);
            }
        };
        let startpos = ranges[0].start as u64;
        let size = ranges[0].length;

        let file = blobs.get(&ffi::OsString::from(&dis)).unwrap().as_raw_fd();

        Ok(StoredData::Range(RangeStream {
            dis: dis.to_string(),
            len: size,
            start: startpos,
            fd: file,
        }))
    }
}

#[rocket::main]
async fn main() {
    let cmd = App::new("nydus-backend-proxy")
        .author(crate_authors!())
        .version(crate_version!())
        .about("A simple HTTP server to serve a local directory as blob backend for nydusd.")
        .arg(
            Arg::with_name("blobsdir")
                .short("b")
                .long("blobsdir")
                .takes_value(true)
                .help("path to nydus blobs dir"),
        )
        .get_matches();
    let path = cmd.value_of("blobsdir").unwrap();

    init_blob_backend(Path::new(path)).await;

    if let Err(e) = rocket::build()
        .mount("/", rocket::routes![check, fetch])
        .mount("/", FileServer::from(&path))
        .launch()
        .await
    {
        panic!("Rocket didn't launch! Err:{:#?}", e);
    }
}
