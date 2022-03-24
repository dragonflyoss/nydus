#[macro_use]
extern crate rocket;
extern crate http_range;
extern crate nix;
#[macro_use(crate_authors, crate_version)]
extern crate clap;

use clap::{App, Arg};
use rocket::fs::FileServer;
use std::env;
use std::path::PathBuf;

mod blob_backend {
    use http_range::HttpRange;
    use nix::sys::uio;
    use once_cell::sync::OnceCell;
    use rocket::fs::NamedFile;
    use rocket::http::Status;
    use rocket::request::{self, FromRequest, Outcome};
    use rocket::response::{self, stream::ReaderStream, Responder};
    use rocket::Request;
    use rocket::Response;
    use std::collections::HashMap;
    use std::os::unix::io::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::{ffi, fs, io};

    #[derive(Debug)]
    struct BlobBackend {
        root: PathBuf,
        blobs: HashMap<ffi::OsString, fs::File>,
    }
    impl BlobBackend {
        fn new(root: PathBuf) -> Self {
            Self {
                blobs: get_blobmap(&root),
                root,
            }
        }
    }
    fn get_blobmap(path: &Path) -> HashMap<ffi::OsString, fs::File> {
        let mut blobfdmap = HashMap::new();
        for entry in path.read_dir().expect("read blobsdir failed").flatten() {
            let filepath = entry.path();
            if filepath.is_file() {
                let digest = filepath.file_name().unwrap();
                let std_file = fs::File::open(&filepath).unwrap();
                blobfdmap.insert(digest.to_os_string(), std_file);
            }
        }
        blobfdmap
    }
    static BLOBBACKEND: OnceCell<BlobBackend> = OnceCell::new();

    pub fn init(root: PathBuf) {
        BLOBBACKEND.set(BlobBackend::new(root)).unwrap();
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
        let blobbackend = match BLOBBACKEND.get() {
            Some(blob) => blob,
            None => {
                eprintln!("BLOBBACKEND get failed!");
                return Err(Status::InternalServerError);
            }
        };
        let path = blobbackend.root.join(&dis);
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
    }

    impl RangeStream {
        fn get_rangestr(&self) -> String {
            let endpos = self.start + self.len - 1;
            format!("bytes {}-{}/{}", self.start, endpos, self.len)
        }
    }

    impl<'r> Responder<'r, 'static> for RangeStream {
        fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
            let blobbackend = match BLOBBACKEND.get() {
                Some(blob) => blob,
                None => {
                    eprintln!("BLOBBACKEND get failed!");
                    return Err(Status::InternalServerError);
                }
            };
            let file = match blobbackend.blobs.get(&ffi::OsString::from(&self.dis)) {
                Some(fd) => fd,
                None => return Err(Status::NotFound),
            };
            let rangestring = self.get_rangestr();
            let size = self.len;
            const BUFSIZE: usize = 4096;
            let mut buf = vec![0; BUFSIZE];
            let mut read = 0;
            let startpos = self.start as i64;
            let raw_fd = file.as_raw_fd();
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
        let blobbackend = match BLOBBACKEND.get() {
            Some(blob) => blob,
            None => {
                eprintln!("BLOBBACKEND get failed!");
                return Err(Status::InternalServerError);
            }
        };
        //if no range in Request header,return fetch blob response
        if headerdata.range.is_empty() {
            let filepath = blobbackend.root.join(&dis);
            return Ok(StoredData::AllFile(
                NamedFile::open(filepath)
                    .await
                    .ok()
                    .map(|nf| FileStream(nf, dis.to_string())),
            ));
        } else {
            let blobfd = match blobbackend.blobs.get(&ffi::OsString::from(&dis)) {
                Some(fd) => fd,
                None => return Err(Status::NotFound),
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
            Ok(StoredData::Range(RangeStream {
                dis: dis.to_string(),
                len: size,
                start: startpos,
            }))
        }
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
    blob_backend::init(PathBuf::from(&path));
    if let Err(e) = rocket::build()
        .mount(
            "/",
            rocket::routes![blob_backend::check, blob_backend::fetch],
        )
        .mount("/", FileServer::from(&path))
        .launch()
        .await
    {
        panic!("Rocket didn't launch! Err:{:#?}", e);
    }
}
