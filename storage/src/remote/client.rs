// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use vm_memory::ByteValued;

use crate::device::BlobInfo;
use crate::remote::connection::Endpoint;
use crate::remote::message::{
    FetchRangeReply, FetchRangeRequest, GetBlobReply, GetBlobRequest, HeaderFlag, MsgHeader,
    MsgValidator, RequestCode,
};
use crate::remote::REQUEST_TIMEOUT_SEC;

#[derive(Debug, Eq, PartialEq)]
enum RequestStatus {
    Waiting,
    Reconnect,
    Timeout,
    Finished,
}

#[allow(dead_code)]
enum RequestResult {
    None,
    Reconnect,
    Noop,
    GetBlob(u32, u64, u64, Option<File>),
    FetchRange(u32, u64),
}

struct Request {
    tag: u64,
    condvar: Condvar,
    state: Mutex<(RequestStatus, RequestResult)>,
}

impl Request {
    fn new(tag: u64) -> Self {
        Request {
            tag,
            condvar: Condvar::new(),
            state: Mutex::new((RequestStatus::Waiting, RequestResult::None)),
        }
    }

    fn wait_for_result(&self) {
        let mut guard = self.state.lock().unwrap();

        while guard.0 == RequestStatus::Waiting {
            let res = self
                .condvar
                .wait_timeout(guard, Duration::from_secs(REQUEST_TIMEOUT_SEC))
                .unwrap();
            let tor = res.1;

            guard = res.0;
            if guard.0 == RequestStatus::Finished || guard.0 == RequestStatus::Reconnect {
                return;
            } else if tor.timed_out() {
                guard.0 = RequestStatus::Timeout;
            }
        }
    }

    fn set_result(&self, result: RequestResult) {
        let mut guard = self.state.lock().unwrap();

        match guard.0 {
            RequestStatus::Waiting | RequestStatus::Timeout | RequestStatus::Reconnect => {
                guard.1 = result;
                guard.0 = RequestStatus::Finished;
                self.condvar.notify_all();
            }
            RequestStatus::Finished => {
                debug!("received duplicated reply");
            }
        }
    }
}

/// Struct to maintain state for a connection to remote blob manager.
pub(crate) struct Client {
    sock: String,
    tag: AtomicU64,
    exiting: AtomicBool,
    conn: Mutex<Option<Endpoint>>,
    ready: Condvar,
    requests: Mutex<HashMap<u64, Arc<Request>>>,
}

impl Client {
    pub fn new(sock: &str) -> Self {
        Client {
            sock: sock.to_owned(),
            tag: AtomicU64::new(1),
            exiting: AtomicBool::new(false),
            conn: Mutex::new(None),
            ready: Condvar::new(),
            requests: Mutex::new(HashMap::new()),
        }
    }

    pub fn connect(&self) -> Result<bool> {
        if self.exiting.load(Ordering::Relaxed) {
            return Err(eio!());
        }

        let mut guard = self.conn.lock().unwrap();
        if guard.is_some() {
            return Ok(false);
        }

        match Endpoint::connect(&self.sock) {
            Ok(v) => {
                *guard = Some(v);
                Ok(true)
            }
            Err(e) => {
                error!("cannot connect to remote blob manager, {}", e);
                Err(eio!())
            }
        }
    }

    pub fn close(&self) {
        if !self.exiting.swap(true, Ordering::AcqRel) {
            self.disconnect();
        }
    }

    pub fn start(client: Arc<Client>) -> Result<()> {
        std::thread::spawn(move || loop {
            if client.exiting.load(Ordering::Relaxed) {
                return;
            }

            let guard = client.conn.lock().unwrap();
            if guard.is_none() {
                drop(client.ready.wait(guard));
            } else {
                drop(guard);
            }

            let _ = client.handle_reply();
        });

        Ok(())
    }

    #[allow(dead_code)]
    pub fn call_ping(&self) -> Result<()> {
        let req = self.create_request();
        let hdr = MsgHeader::new(
            req.tag,
            RequestCode::Noop,
            HeaderFlag::NEED_REPLY.bits(),
            0u32,
        );
        let msg = [0u8; 0];

        loop {
            self.send_msg(&hdr, &msg)?;
            match self.wait_for_result(&req)? {
                RequestResult::Noop => return Ok(()),
                RequestResult::Reconnect => {}
                //_ => return Err(eother!()),
                _ => panic!("unknown code"),
            }
        }
    }

    pub fn call_get_blob(&self, blob_info: &Arc<BlobInfo>) -> Result<(File, u64, u64)> {
        if blob_info.blob_id().len() >= 256 {
            return Err(einval!("blob id is too large"));
        }

        let req = self.create_request();
        let hdr = MsgHeader::new(
            req.tag,
            RequestCode::GetBlob,
            HeaderFlag::NEED_REPLY.bits(),
            std::mem::size_of::<GetBlobRequest>() as u32,
        );
        let msg = GetBlobRequest::new(blob_info.blob_id());

        loop {
            self.send_msg(&hdr, &msg)?;
            match self.wait_for_result(&req)? {
                RequestResult::GetBlob(result, token, base, file) => {
                    if result != 0 {
                        return Err(std::io::Error::from_raw_os_error(result as i32));
                    } else if let Some(file) = file {
                        return Ok((file, base, token));
                    } else {
                        return Err(einval!());
                    }
                }
                RequestResult::Reconnect => {}
                _ => return Err(eother!()),
            }
        }
    }

    pub fn call_fetch_range(&self, token: u64, start: u64, count: u64) -> Result<usize> {
        let req = self.create_request();
        let hdr = MsgHeader::new(
            req.tag,
            RequestCode::FetchRange,
            HeaderFlag::NEED_REPLY.bits(),
            std::mem::size_of::<GetBlobRequest>() as u32,
        );
        let msg = FetchRangeRequest::new(token, start, count);

        loop {
            self.send_msg(&hdr, &msg)?;
            match self.wait_for_result(&req)? {
                RequestResult::FetchRange(result, size) => {
                    if result == 0 {
                        return Ok(size as usize);
                    } else {
                        return Err(std::io::Error::from_raw_os_error(result as i32));
                    }
                }
                RequestResult::Reconnect => {}
                _ => return Err(eother!()),
            }
        }
    }

    pub fn handle_reply(&self) -> Result<()> {
        loop {
            match self.conn.lock().unwrap().as_mut() {
                None => return Err(eio!()),
                Some(conn) => {
                    let (hdr, files) = conn.recv_header().map_err(|_e| eio!())?;
                    if !hdr.is_valid() {
                        return Err(einval!());
                    }
                    let body_size = hdr.get_size() as usize;

                    match hdr.get_code() {
                        RequestCode::MaxCommand => return Err(eother!()),
                        RequestCode::Noop => self.handle_result(hdr.get_tag(), RequestResult::Noop),
                        RequestCode::GetBlob => {
                            self.handle_get_blob_reply(conn, &hdr, body_size, files)?;
                        }
                        RequestCode::FetchRange => {
                            self.handle_fetch_range_reply(conn, &hdr, body_size, files)?;
                        }
                    }
                }
            }
        }
    }

    fn get_next_tag(&self) -> u64 {
        self.tag.fetch_add(1, Ordering::AcqRel)
    }

    fn create_request(&self) -> Arc<Request> {
        let tag = self.get_next_tag();
        let request = Arc::new(Request::new(tag));

        self.requests.lock().unwrap().insert(tag, request.clone());

        request
    }

    fn get_connection(&self) -> Result<MutexGuard<Option<Endpoint>>> {
        if self.exiting.load(Ordering::Relaxed) {
            Err(eio!())
        } else {
            Ok(self.conn.lock().unwrap())
        }
    }

    fn send_msg<T: Sized>(&self, hdr: &MsgHeader, msg: &T) -> Result<()> {
        if let Ok(mut guard) = self.get_connection() {
            if let Some(conn) = guard.as_mut() {
                if conn.send_message(hdr, msg, None).is_ok() {
                    return Ok(());
                }
            }
        }
        self.disconnect();

        let start = Instant::now();
        loop {
            self.reconnect();

            if let Ok(mut guard) = self.get_connection() {
                if let Some(conn) = guard.as_mut() {
                    if conn.send_message(hdr, msg, None).is_ok() {
                        return Ok(());
                    }
                }
            }
            self.disconnect();

            if let Some(end) = start.checked_add(Duration::from_secs(REQUEST_TIMEOUT_SEC)) {
                let now = Instant::now();
                if end < now {
                    return Err(eio!());
                }
            } else {
                return Err(eio!());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn reconnect(&self) {
        if let Ok(true) = self.connect() {
            let guard = self.requests.lock().unwrap();
            for entry in guard.iter() {
                let mut state = entry.1.state.lock().unwrap();
                state.0 = RequestStatus::Reconnect;
                entry.1.condvar.notify_all();
            }
        }
    }

    fn disconnect(&self) {
        let mut guard = self.conn.lock().unwrap();
        if let Some(conn) = guard.as_mut() {
            conn.close();
        }
        *guard = None;
    }

    fn wait_for_result(&self, request: &Arc<Request>) -> Result<RequestResult> {
        request.wait_for_result();

        let mut guard = self.requests.lock().unwrap();
        match guard.remove(&request.tag) {
            None => Err(enoent!()),
            Some(entry) => {
                let mut guard2 = entry.state.lock().unwrap();
                match guard2.0 {
                    RequestStatus::Waiting => panic!("should not happen"),
                    RequestStatus::Timeout => Err(eio!()),
                    RequestStatus::Finished => {
                        let mut val = RequestResult::None;
                        mem::swap(&mut guard2.1, &mut val);
                        Ok(val)
                    }
                    RequestStatus::Reconnect => {
                        guard2.0 = RequestStatus::Waiting;
                        guard.insert(request.tag, request.clone());
                        Ok(RequestResult::Reconnect)
                    }
                }
            }
        }
    }

    fn handle_result(&self, tag: u64, result: RequestResult) {
        let requests = self.requests.lock().unwrap();

        match requests.get(&tag) {
            None => debug!("no request for tag {} found, may have timed out", tag),
            Some(request) => request.set_result(result),
        }
    }

    fn handle_get_blob_reply(
        &self,
        conn: &mut Endpoint,
        hdr: &MsgHeader,
        body_size: usize,
        files: Option<Vec<File>>,
    ) -> Result<()> {
        if body_size != mem::size_of::<GetBlobReply>() {
            return Err(einval!());
        }
        let (size, data) = conn.recv_data(body_size).map_err(|_e| eio!())?;
        if size != body_size {
            return Err(eio!());
        }
        let mut msg = GetBlobReply::new(0, 0, 0);
        msg.as_mut_slice().copy_from_slice(&data);
        if !msg.is_valid() {
            return Err(einval!());
        }

        if msg.result != 0 {
            self.handle_result(
                hdr.get_tag(),
                RequestResult::GetBlob(msg.result, msg.token, msg.base, None),
            );
        } else {
            if files.is_none() {
                return Err(einval!());
            }
            // Safe because we have just validated files is not none.
            let mut files = files.unwrap();
            if files.len() != 1 {
                return Err(einval!());
            }
            // Safe because we have just validated files[0] is valid.
            let file = files.pop().unwrap();
            self.handle_result(
                hdr.get_tag(),
                RequestResult::GetBlob(msg.result, msg.token, msg.base, Some(file)),
            );
        }

        Ok(())
    }

    fn handle_fetch_range_reply(
        &self,
        conn: &mut Endpoint,
        hdr: &MsgHeader,
        body_size: usize,
        files: Option<Vec<File>>,
    ) -> Result<()> {
        if body_size != mem::size_of::<FetchRangeReply>() || files.is_some() {
            return Err(einval!());
        }
        let (size, data) = conn.recv_data(body_size).map_err(|_e| eio!())?;
        if size != body_size {
            return Err(eio!());
        }

        let mut msg = FetchRangeReply::new(0, 0, 0);
        msg.as_mut_slice().copy_from_slice(&data);
        if !msg.is_valid() {
            return Err(einval!());
        } else {
            self.handle_result(
                hdr.get_tag(),
                RequestResult::FetchRange(msg.result, msg.count),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request() {
        let req = Arc::new(Request::new(1));
        let req1 = req.clone();

        assert_eq!(req.tag, 1);
        {
            let guard = req.state.lock().unwrap();
            assert_eq!(guard.0, RequestStatus::Waiting);
            matches!(guard.1, RequestResult::None);
        }

        let (sender, receiver) = std::sync::mpsc::channel::<bool>();
        std::thread::spawn(move || {
            let _ = receiver.recv().unwrap();
            {
                let mut guard = req1.state.lock().unwrap();
                guard.0 = RequestStatus::Reconnect;
            }

            let _ = receiver.recv().unwrap();
            req1.set_result(RequestResult::Reconnect);
        });

        {
            req.wait_for_result();
            let mut guard = req.state.lock().unwrap();
            assert_eq!(guard.0, RequestStatus::Timeout);
            guard.0 = RequestStatus::Waiting;
        }

        sender.send(true).unwrap();
        {
            req.wait_for_result();
            let mut guard = req.state.lock().unwrap();
            assert_eq!(guard.0, RequestStatus::Reconnect);
            guard.0 = RequestStatus::Waiting;
        }

        sender.send(true).unwrap();
        {
            req.wait_for_result();
            let guard = req.state.lock().unwrap();
            assert_eq!(guard.0, RequestStatus::Finished);
            matches!(guard.1, RequestResult::Reconnect);
        }
    }
}
