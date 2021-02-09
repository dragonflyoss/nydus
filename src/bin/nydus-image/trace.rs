// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Trace image building procedure

use std::any::Any;
use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{self, Write};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::{error::Error, value::Value};

impl Display for TraceClass {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            TraceClass::Timing => write!(f, "consumed_time"),
        }
    }
}

macro_rules! enum_str {
    ($m:meta
    pub enum $name:ident {
        $($variant:ident = $val:expr),*,
    }) => {
        #[$m]
        pub enum $name {
            $($variant = $val),*
        }

        impl $name {
            fn name(&self) -> String {
                match self {
                    $($name::$variant => format!("{}", $name::$variant)),*
                }
            }
        }
    };
}

enum_str! {
derive(Hash, Eq, PartialEq)
pub enum TraceClass {
    Timing = 1,
}
}
pub enum TraceError {
    Serde(Error),
}

type Result<T> = std::result::Result<T, TraceError>;

/// Used to measure time consuming and gather all tracing points when building image.
#[derive(Serialize, Default)]
pub struct TimingTracerClass {
    records: Mutex<HashMap<String, f32>>,
}

pub trait TracerClass: Send + Sync + 'static {
    fn release(&self) -> Result<Value>;
    fn as_any(&self) -> &dyn Any;
}

impl TracerClass for TimingTracerClass {
    fn release(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(TraceError::Serde)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn trace_timing<F: FnOnce() -> T, T>(point: &str, tracer: &TimingTracerClass, f: F) -> T {
    let begin = SystemTime::now();
    let r = f();
    let elapsed = SystemTime::now().duration_since(begin).unwrap();

    // Not expect poisoned lock.
    tracer
        .records
        .lock()
        .unwrap()
        .insert(point.to_string(), elapsed.as_secs_f32());

    r
}

/// The root tracer manages all kinds of tracers registered to it.
/// The statistics/events/records can be printed out or persisted from the root
/// tracer. When building procedure is finished, root tracer can dump all tracing
/// points to specified output file.
pub struct BuildRootTracer {
    tracers: RwLock<HashMap<TraceClass, Arc<dyn TracerClass>>>,
}

impl BuildRootTracer {
    pub fn register(&self, class: TraceClass, tracer: Arc<dyn TracerClass>) {
        let mut guard = self.tracers.write().unwrap();
        guard.insert(class, tracer);
    }

    pub fn tracer(&self, class: TraceClass) -> Arc<dyn TracerClass> {
        let g = self.tracers.read().unwrap();
        // Safe to unwrap because tracers should always be enabled
        (&g).get(&class).unwrap().clone()
    }

    pub fn dump_summary(&self, w: &mut dyn io::Write) -> Result<()> {
        let mut map = serde_json::Map::new();
        for c in self.tracers.write().unwrap().iter() {
            map.insert(c.0.name(), c.1.release()?);
        }

        serde_json::to_writer(w, &map).map_err(TraceError::Serde)?;

        #[allow(clippy::write_with_newline)]
        write!(io::stdout(), "\n").unwrap_or_default();

        Ok(())
    }
}

lazy_static! {
    pub static ref BUILDING_RECORDER: BuildRootTracer = BuildRootTracer {
        tracers: RwLock::new(HashMap::default())
    };
}

#[macro_export]
macro_rules! root_tracer {
    () => {
        &BUILDING_RECORDER as &BuildRootTracer
    };
}

#[macro_export]
macro_rules! timing_tracer {
    () => {
        root_tracer!()
            .tracer(TraceClass::Timing)
            .as_any()
            .downcast_ref::<TimingTracerClass>()
            .unwrap()
    };
    ($f:block, $key:expr) => {
        trace_timing($key, timing_tracer!(), || $f)
    };
    ($f:block, $key:expr, $t:ty) => {
        trace_timing::<_, $t>($key, timing_tracer!(), || $f)
    };
}

#[macro_export]
macro_rules! register_tracer {
    ($class:expr, $r:ty) => {
        root_tracer!().register($class, Arc::new(<$r>::default()));
    };
}
