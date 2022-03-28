// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::io::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::ArgMatches;
use serde_json::Value;
use storage::device::{BlobFeatures, BlobInfo};
use storage::factory::FactoryConfig;

use crate::fscache::FsCacheHandler;
use crate::SERVICE_CONTROLLER;

pub struct ServiceContoller {
    fscache_enabled: AtomicBool,
    fscache: Mutex<Option<Arc<FsCacheHandler>>>,
}

impl ServiceContoller {
    pub fn new() -> Self {
        ServiceContoller {
            fscache: Mutex::new(None),
            fscache_enabled: AtomicBool::new(false),
        }
    }

    /// Process commandline options related to services.
    pub fn process_arguments(
        &self,
        args: &ArgMatches,
        subargs: &ArgMatches,
        _apisock: Option<&str>,
    ) -> Result<()> {
        let config = match args.value_of("config") {
            None => None,
            Some(path) => {
                let config = std::fs::read_to_string(path)?;
                let config: serde_json::Value = serde_json::from_str(&config)
                    .map_err(|_e| einval!("invalid configuration file"))?;
                Some(config)
            }
        };
        if let Some(path) = subargs.value_of("fscache") {
            self.initialize_fscache_service(path, &config)?;
        }

        Ok(())
    }

    /// Start all enabled services.
    pub fn start_services(&self) -> Result<()> {
        info!("Starting all Nydus services...");
        if self.fscache_enabled.load(Ordering::Acquire) {
            if let Some(fscache) = self.fscache.lock().unwrap().clone() {
                std::thread::spawn(move || {
                    if let Err(e) = fscache.run_loop() {
                        error!("Failed to run fscache service loop, {}", e);
                    }
                    // Notify the global service controller that one working thread is exiting.
                    if let Err(e) = SERVICE_CONTROLLER.waker.wake() {
                        error!("Failed to notify the global service controller, {}", e);
                    }
                });
            }
        }

        Ok(())
    }

    /// Stop all enabled services.
    pub fn stop_services(&self) {
        info!("Stopping all Nydus services...");
        if self.fscache_enabled.load(Ordering::Acquire) {
            if let Some(fscache) = self.fscache.lock().unwrap().take() {
                fscache.stop();
            }
        }
    }

    fn initialize_fscache_service(&self, path: &str, config: &Option<Value>) -> Result<()> {
        println!("{}", path);
        let fscache = FsCacheHandler::new(path, "/tmp/fscache", None)?;
        if let Some(config) = config {
            let factory_config: FactoryConfig = serde_json::from_value(config.to_owned())
                .map_err(|_e| eother!("invalid configuration file"))?;
            let blob_info = BlobInfo::new(
                1,
                "blob_id".to_string(),
                0x10000,
                0x8000,
                0x1000,
                1,
                BlobFeatures::empty(),
            );
            fscache.add_blob_object(Arc::new(blob_info), Arc::new(factory_config))?;
        }

        *self.fscache.lock().unwrap() = Some(Arc::new(fscache));
        self.fscache_enabled.store(true, Ordering::Release);

        Ok(())
    }
}
