// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;

use crate::client::NydusdClient;
use anyhow::Result;

use nydus::FsBackendDesc;
use rafs::fs::RafsConfig;

type CommandParams = HashMap<String, String>;

pub(crate) struct CommandBlobcache {}

impl CommandBlobcache {
    pub async fn execute(
        &self,
        raw: bool,
        client: &NydusdClient,
        _params: Option<CommandParams>,
    ) -> Result<()> {
        let metrics = client.get("metrics/blobcache").await?;
        let m = metrics.as_object().unwrap();

        if raw {
            println!("{}", metrics.to_string());
        } else {
            print!(
                r#"
Partial Hits:       {partial_hits}
Whole Hits:         {whole_hits}
Total Read:         {total_read}
Prefetch Amount:    {prefetch_amount} = {prefetch_amount_kb}KB
"#,
                partial_hits = m["partial_hits"],
                whole_hits = m["whole_hits"],
                total_read = m["total"],
                prefetch_amount = m["prefetch_data_amount"],
                prefetch_amount_kb = m["prefetch_data_amount"].as_u64().unwrap() / 1024,
            );
        }

        Ok(())
    }
}

pub(crate) struct CommandBackend {}

impl CommandBackend {
    pub async fn execute(
        &self,
        raw: bool,
        client: &NydusdClient,
        params: Option<CommandParams>,
    ) -> Result<()> {
        let metrics = client.get("metrics/backend").await?;

        let interval: Option<Result<u32>> =
            params.and_then(|p| p.get("interval").cloned()).map(|i| {
                i.parse()
                    .map_err(|e| anyhow!("Invalid interval input. {}", e))
            });

        if let Some(Err(e)) = interval {
            return Err(e);
        } else if let Some(Ok(i)) = interval {
            let mut last_record = metrics;
            loop {
                sleep(Duration::from_secs(i as u64));

                let newest = client.get("metrics/backend").await?;

                let delta = newest["read_amount_total"].as_u64().unwrap()
                    - last_record["read_amount_total"].as_u64().unwrap();
                let bw = delta / i as u64 / 1024;

                println!("Backend read bandwidth {}KB/S", bw);

                last_record = newest;
            }
        }

        if raw {
            println!("{}", metrics.to_string());
        } else {
            let m = metrics.as_object().unwrap();
            print!(
                r#"
Backend Type:       {backend_type}
Read Amount:        {read_amount} Bytes ({read_count_mb} MB)
Read Count:         {read_count}
Read Errors:        {read_errors}
"#,
                backend_type = m["backend_type"],
                read_amount = m["read_amount_total"],
                read_count = m["read_count"],
                read_count_mb = m["read_amount_total"].as_f64().unwrap() / 1024.0 / 1024.0,
                read_errors = m["read_errors"],
            );
        }

        Ok(())
    }
}

pub(crate) struct CommandFsStats {}

impl CommandFsStats {
    pub async fn execute(
        &self,
        raw: bool,
        client: &NydusdClient,
        _params: Option<CommandParams>,
    ) -> Result<()> {
        let metrics = client.get("metrics").await?;
        let m = metrics.as_object().unwrap();
        let fop_counter = m["fop_hits"].as_array().unwrap();
        if raw {
            println!("{}", metrics.to_string());
        } else {
            print!(
                r#"
FOP Counters:
Getattr({}) Readlink({}) Open({}) Release({}) Read({}) Statfs({}) Getxattr({}) Listxattr({})
Opendir({}) Lookup({}) Readdir({}) Readdirplus({}) Access({}) Forget({}) BatchForget({})
"#,
                fop_counter[0],
                fop_counter[1],
                fop_counter[2],
                fop_counter[3],
                fop_counter[4],
                fop_counter[5],
                fop_counter[6],
                fop_counter[7],
                fop_counter[8],
                fop_counter[9],
                fop_counter[10],
                fop_counter[11],
                fop_counter[12],
                fop_counter[13],
                fop_counter[14],
            );
        }

        Ok(())
    }
}

pub(crate) struct CommandDaemon {}

impl CommandDaemon {
    pub async fn execute(
        &self,
        raw: bool,
        client: &NydusdClient,
        params: Option<CommandParams>,
    ) -> Result<()> {
        if let Some(p) = params {
            let data = serde_json::to_string(&p)?;
            client.put("daemon", Some(data)).await?;
        } else {
            let info = client.get("daemon").await?;
            let i = info.as_object().unwrap();

            let backend_list = i["backend_collection"].as_object().unwrap();

            if raw {
                println!("{}", info.to_string());
            } else {
                let version_info = &i["version"];
                print!(
                    r#"
Version:                {version}
Status:                 {state}
Profile:                {profile}"#,
                    version = version_info["package_ver"],
                    state = i["state"],
                    profile = version_info["profile"],
                );

                for f in backend_list.values() {
                    let backend: FsBackendDesc = serde_json::from_value(f.clone()).unwrap();
                    let fs: RafsConfig = serde_json::from_value(backend.config.clone()).unwrap();
                    print!(
                        r#"
Mode:                   {meta_mode}
Prefetch:               {enabled}
Prefetch Merging Size:  {merging_size}
"#,
                        meta_mode = fs.mode,
                        enabled = fs.fs_prefetch.enable,
                        merging_size = fs.fs_prefetch.merging_size,
                    );
                }
            }
        }

        Ok(())
    }
}
