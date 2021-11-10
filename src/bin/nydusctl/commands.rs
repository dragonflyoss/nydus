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

fn load_param_interval(params: &Option<CommandParams>) -> Result<Option<u32>> {
    if let Some(p) = params {
        if let Some(interval) = p.get("interval") {
            interval
                .parse()
                .map(Some)
                .map_err(|e| anyhow!("Invalid interval input. {}", e))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub(crate) struct CommandBlobcache {}

macro_rules! items_map(
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m: HashMap<String, String> = HashMap::new();
            $(
                m.insert($key.to_string(), $value.to_string());
            )+
            m
        }
     };
);

lazy_static! {
    pub static ref CONFIGURE_ITEMS_MAP: HashMap<String, String> =
        items_map!("log-level" => "log_level");
}

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
Partial Hits:           {partial_hits}
Whole Hits:             {whole_hits}
Total Read:             {total_read}
Directory:              {directory}
Files:                  {files}
Prefetch Workers:       {workers}
Prefetch Amount:        {prefetch_amount} = {prefetch_amount_kb} KB
Prefetch Requests:      {requests}
Prefetch Average Size:  {avg_prefetch_size} Bytes
Prefetch Unmerged:      {unmerged_blocks}
Persister Buffer:       {buffered}
"#,
                partial_hits = m["partial_hits"],
                whole_hits = m["whole_hits"],
                total_read = m["total"],
                prefetch_amount = m["prefetch_data_amount"],
                prefetch_amount_kb = m["prefetch_data_amount"].as_u64().unwrap() / 1024,
                files = m["underlying_files"],
                directory = m["store_path"],
                requests = m["prefetch_mr_count"],
                avg_prefetch_size = m["prefetch_data_amount"]
                    .as_u64()
                    .unwrap()
                    .checked_div(m["prefetch_mr_count"].as_u64().unwrap())
                    .unwrap_or_default(),
                workers = m["prefetch_workers"],
                unmerged_blocks = m["prefetch_unmerged_chunks"],
                buffered = m["buffered_backend_size"],
            );
        }

        Ok(())
    }
}

fn metric_delta(old: &serde_json::Value, new: &serde_json::Value, label: &str) -> u64 {
    new[label].as_u64().unwrap() - old[label].as_u64().unwrap()
}

fn metric_vec_delta(old: &serde_json::Value, new: &serde_json::Value, label: &str) -> Vec<u64> {
    let new_array = new[label].as_array().unwrap();
    let old_array = old[label].as_array().unwrap();
    assert_eq!(new_array.len(), old_array.len());
    let mut r = Vec::new();

    for i in 0..new_array.len() {
        r.push(new_array[i].as_u64().unwrap() - old_array[i].as_u64().unwrap());
    }

    r
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

        let interval = load_param_interval(&params)?;
        if let Some(i) = interval {
            let mut last = metrics;
            loop {
                sleep(Duration::from_secs(i as u64));
                let current = client.get("metrics/backend").await?;

                let delta_data = metric_delta(&last, &current, "read_amount_total");
                let delta_requests = metric_delta(&last, &current, "read_count");
                let delta_latency =
                    metric_delta(&last, &current, "read_cumulative_latency_millis_total");
                // Block size separated counters.
                // 1K; 4K; 16K; 64K, 128K, 512K, 1M
                // <=1ms, <=20ms, <=50ms, <=100ms, <=500ms, <=1s, <=2s, >2s

                // TODO: Also add 256k
                let latency_cumulative_dist =
                    metric_vec_delta(&last, &current, "read_cumulative_latency_millis_dist");
                let latency_block_hits =
                    metric_vec_delta(&last, &current, "read_count_block_size_dist");

                let sizes = vec!["<1K", "1K~", "4K~", "16K~", "64K~", "128K~", "512K~", "1M~"];

                print!(
                    r#"
>>> >>> >>> >>> >>>
Backend Read Bandwidth:     {} KB/S
Backend Average IO Size:    {} Bytes
Backend Average Latency:    {} millis

Block Sizes/millis:
{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}
"#,
                    delta_data.checked_div(i as u64 * 1024).unwrap_or_default(),
                    delta_data.checked_div(delta_requests).unwrap_or_default(),
                    delta_latency
                        .checked_div(delta_requests)
                        .unwrap_or_default(),
                    sizes[0],
                    sizes[1],
                    sizes[2],
                    sizes[3],
                    sizes[4],
                    sizes[5],
                    sizes[6],
                    sizes[7]
                );

                for (i, _) in sizes.iter().enumerate() {
                    print!(
                        "{:<8}",
                        latency_cumulative_dist[i]
                            .checked_div(latency_block_hits[i])
                            .unwrap_or_default()
                    );
                }

                println!();
                println!("<<< <<< <<< <<< <<<");

                last = current;
            }
        }

        if raw {
            println!("{}", metrics.to_string());
        } else {
            let sizes = vec!["<1K", "1K~", "4K~", "16K~", "64K~", "128K~", "512K~", "1M~"];
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

            println!(
                r#"
Block Sizes/millis:
{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}"#,
                sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], sizes[5], sizes[6], sizes[7]
            );

            let latency_cumulative_dist =
                m["read_cumulative_latency_millis_dist"].as_array().unwrap();
            let latency_block_hits = m["read_count_block_size_dist"].as_array().unwrap();

            for (i, _) in sizes.iter().enumerate() {
                print!(
                    "{:<8}",
                    latency_cumulative_dist[i]
                        .as_u64()
                        .unwrap()
                        .checked_div(latency_block_hits[i].as_u64().unwrap())
                        .unwrap_or_default()
                );
            }

            println!();

            println!(
                r#"
Block Sizes:
{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}"#,
                sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], sizes[5], sizes[6], sizes[7]
            );

            for (i, _) in sizes.iter().enumerate() {
                print!("{:<8}", latency_block_hits[i].as_u64().unwrap());
            }

            println!();
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
            let mut real = HashMap::<String, String>::new();

            // Map user provided configured item key to the one nydusd accepts.
            for (k, v) in p.into_iter() {
                real.insert(
                    CONFIGURE_ITEMS_MAP
                        .get(&k)
                        .ok_or_else(|| anyhow!("illegal item input"))?
                        .clone(),
                    v,
                );
            }

            let data = serde_json::to_string(&real)?;
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

pub(crate) struct CommandMount {}

impl CommandMount {
    pub async fn execute(
        &self,
        _raw: bool,
        client: &NydusdClient,
        params: Option<CommandParams>,
    ) -> Result<()> {
        let p = params.unwrap();
        let (source, mountpoint, fs_type) = (&p["source"], &p["mountpoint"], &p["type"]);
        let config = std::fs::read_to_string(&p["config"]).unwrap();
        let cmd = json!({"source": source, "fs_type": fs_type, "config": config}).to_string();

        client
            .post("mount", Some(cmd), Some(vec![("mountpoint", mountpoint)]))
            .await
    }
}

pub(crate) struct CommandUmount {}

impl CommandUmount {
    pub async fn execute(
        &self,
        _raw: bool,
        client: &NydusdClient,
        params: Option<CommandParams>,
    ) -> Result<()> {
        let p = params.unwrap();
        let mountpoint = &p["mountpoint"];

        client
            .delete("mount", None, Some(vec![("mountpoint", &mountpoint)]))
            .await
    }
}
