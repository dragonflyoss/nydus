// Copyright (C) 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Deduplicate for Chunk.
use anyhow::{Context, Result};
use core::cmp::Ordering;
use nydus_api::ConfigV2;
use nydus_builder::BuildContext;
use nydus_builder::ConversionType;
use nydus_builder::Tree;
use nydus_builder::{ChunkdictBlobInfo, ChunkdictChunkInfo};
use nydus_rafs::metadata::{RafsSuper, RafsVersion};
use nydus_storage::device::BlobInfo;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};
use std::result::Result::Ok;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub enum DatabaseError {
    SqliteError(rusqlite::Error),
    PoisonError(String),
    // Add other database error variants here as needed, e.g.:
    // MysqlError(mysql::Error).
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            DatabaseError::SqliteError(ref err) => err.fmt(f),
            DatabaseError::PoisonError(ref err) => write!(f, "PoisonError: {}", err),
            // Add other error type formatting here.
        }
    }
}

impl std::error::Error for DatabaseError {}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        DatabaseError::SqliteError(error)
    }
}

pub trait Database {
    /// Creates a new chunk in the database.
    fn create_chunk_table(&self) -> Result<()>;

    /// Creates a new blob in the database.
    fn create_blob_table(&self) -> Result<()>;

    /// Inserts chunk information into the database.
    fn insert_chunk(&self, chunk_info: &ChunkdictChunkInfo) -> Result<()>;

    /// Inserts blob information into the database.
    fn insert_blob(&self, blob_info: &ChunkdictBlobInfo) -> Result<()>;

    /// Retrieves all chunk information from the database.
    fn get_chunks(&self) -> Result<Vec<ChunkdictChunkInfo>>;

    /// Retrieves all chunk information from the database filtered by blob ID.
    fn get_chunks_by_blob_id(&self, blob_id: &str) -> Result<Vec<ChunkdictChunkInfo>>;

    /// Retrieves all blob information from the database.
    fn get_blobs(&self) -> Result<Vec<ChunkdictBlobInfo>>;

    /// Retrieves blob information from the database filtered by blob ID.
    fn get_blob_by_id(&self, blob_id: &str) -> Result<ChunkdictBlobInfo>;
}

pub struct SqliteDatabase {
    chunk_table: ChunkTable,
    blob_table: BlobTable,
}

impl SqliteDatabase {
    pub fn new(database_url: &str) -> Result<Self, rusqlite::Error> {
        // Connect to a database that already exists.
        if let Ok(metadata) = fs::metadata(database_url) {
            if metadata.is_file() {
            } else {
                panic!("Warning: Unable to find existing database file.");
            }
        }

        let chunk_table = ChunkTable::new(database_url)?;
        let blob_table = BlobTable::new(database_url)?;

        Ok(Self {
            chunk_table,
            blob_table,
        })
    }

    pub fn new_in_memory() -> Result<Self, rusqlite::Error> {
        let chunk_table = ChunkTable::new_in_memory()?;
        let blob_table = BlobTable::new_in_memory()?;
        Ok(Self {
            chunk_table,
            blob_table,
        })
    }
}

impl Database for SqliteDatabase {
    fn create_chunk_table(&self) -> Result<()> {
        ChunkTable::create(&self.chunk_table).context("Failed to create chunk table")
    }

    fn create_blob_table(&self) -> Result<()> {
        BlobTable::create(&self.blob_table).context("Failed to create blob table")
    }

    fn insert_chunk(&self, chunk: &ChunkdictChunkInfo) -> Result<()> {
        self.chunk_table
            .insert(chunk)
            .context("Failed to insert chunk")
    }

    fn insert_blob(&self, blob: &ChunkdictBlobInfo) -> Result<()> {
        self.blob_table
            .insert(blob)
            .context("Failed to insert blob")
    }

    fn get_chunks(&self) -> Result<Vec<ChunkdictChunkInfo>> {
        ChunkTable::list_all(&self.chunk_table).context("Failed to get chunks")
    }

    fn get_chunks_by_blob_id(&self, blob_id: &str) -> Result<Vec<ChunkdictChunkInfo>> {
        ChunkTable::list_all_by_blob_id(&self.chunk_table, blob_id).context("Failed to get chunks")
    }

    fn get_blobs(&self) -> Result<Vec<ChunkdictBlobInfo>> {
        BlobTable::list_all(&self.blob_table).context("Failed to get blobs")
    }

    fn get_blob_by_id(&self, blob_id: &str) -> Result<ChunkdictBlobInfo> {
        BlobTable::list_by_id(&self.blob_table, blob_id).context("Failed to get blob")
    }
}

/// Get fs version from bootstrap file.
fn get_fs_version(bootstrap_path: &Path) -> Result<RafsVersion> {
    let (sb, _) = RafsSuper::load_from_file(bootstrap_path, Arc::new(ConfigV2::default()), false)?;
    RafsVersion::try_from(sb.meta.version).context("Failed to get RAFS version number")
}

/// Checks if all Bootstrap versions are consistent.
/// If they are inconsistent, returns an error and prints the version of each Bootstrap.
pub fn check_bootstrap_versions_consistency(
    ctx: &mut BuildContext,
    bootstrap_paths: &[PathBuf],
) -> Result<()> {
    let mut versions = Vec::new();

    for bootstrap_path in bootstrap_paths {
        let version = get_fs_version(bootstrap_path)?;
        versions.push((bootstrap_path.clone(), version));
    }

    if !versions.is_empty() {
        let first_version = versions[0].1;
        ctx.fs_version = first_version;
        if versions.iter().any(|(_, v)| *v != first_version) {
            for (path, version) in &versions {
                println!("Bootstrap path {:?} has version {:?}", path, version);
            }
            return Err(anyhow!(
                "Bootstrap versions are inconsistent, cannot use chunkdict."
            ));
        }
    }

    Ok(())
}

// Get parent bootstrap context for chunkdict bootstrap.
pub fn update_ctx_from_parent_bootstrap(
    ctx: &mut BuildContext,
    bootstrap_path: &PathBuf,
) -> Result<()> {
    let (sb, _) = RafsSuper::load_from_file(bootstrap_path, Arc::new(ConfigV2::default()), false)?;

    // Obtain the features of the first blob to use as the features for the blobs in chunkdict.
    if let Some(first_blob) = sb.superblock.get_blob_infos().first() {
        ctx.blob_features = first_blob.features();
    }

    let config = sb.meta.get_config();
    config.check_compatibility(&sb.meta)?;

    if config.is_tarfs_mode {
        ctx.conversion_type = ConversionType::TarToTarfs;
    }
    ctx.fs_version =
        RafsVersion::try_from(sb.meta.version).context("Failed to get RAFS version")?;
    ctx.compressor = config.compressor;

    Ok(())
}

pub struct Deduplicate<D: Database + Send + Sync> {
    db: D,
}

const IN_MEMORY_DB_URL: &str = ":memory:";

impl Deduplicate<SqliteDatabase> {
    pub fn new(db_url: &str) -> anyhow::Result<Self> {
        let db = if db_url == IN_MEMORY_DB_URL {
            SqliteDatabase::new_in_memory()?
        } else {
            SqliteDatabase::new(db_url)?
        };
        Ok(Self { db })
    }

    pub fn save_metadata(
        &mut self,
        bootstrap_path: &Path,
        config: Arc<ConfigV2>,
        image_reference: String,
        version: String,
    ) -> anyhow::Result<Vec<Arc<BlobInfo>>> {
        let (sb, _) = RafsSuper::load_from_file(bootstrap_path, config, false)?;
        self.create_tables()?;
        let blob_infos = sb.superblock.get_blob_infos();
        self.insert_blobs(&blob_infos)?;
        self.insert_chunks(&blob_infos, &sb, image_reference, version)?;
        Ok(blob_infos)
    }

    fn create_tables(&mut self) -> anyhow::Result<()> {
        self.db
            .create_chunk_table()
            .context("Failed to create chunk table.")?;
        self.db
            .create_blob_table()
            .context("Failed to create blob table.")?;
        Ok(())
    }

    fn insert_blobs(&mut self, blob_infos: &[Arc<BlobInfo>]) -> anyhow::Result<()> {
        for blob in blob_infos {
            self.db
                .insert_blob(&ChunkdictBlobInfo {
                    blob_id: blob.blob_id().to_string(),
                    blob_compressed_size: blob.compressed_size(),
                    blob_uncompressed_size: blob.uncompressed_size(),
                    blob_compressor: blob.compressor().to_string(),
                    blob_meta_ci_compressed_size: blob.meta_ci_compressed_size(),
                    blob_meta_ci_uncompressed_size: blob.meta_ci_uncompressed_size(),
                    blob_meta_ci_offset: blob.meta_ci_offset(),
                })
                .context("Failed to insert blob")?;
        }
        Ok(())
    }

    fn insert_chunks(
        &mut self,
        blob_infos: &[Arc<BlobInfo>],
        sb: &RafsSuper,
        image_reference: String,
        version: String,
    ) -> anyhow::Result<()> {
        let process_chunk = &mut |t: &Tree| -> Result<()> {
            let node = t.borrow_mut_node();
            for chunk in &node.chunks {
                let index = chunk.inner.blob_index();
                let chunk_blob_id = blob_infos[index as usize].blob_id();
                self.db
                    .insert_chunk(&ChunkdictChunkInfo {
                        image_reference: image_reference.to_string(),
                        version: version.to_string(),
                        chunk_blob_id,
                        chunk_digest: chunk.inner.id().to_string(),
                        chunk_compressed_size: chunk.inner.compressed_size(),
                        chunk_uncompressed_size: chunk.inner.uncompressed_size(),
                        chunk_compressed_offset: chunk.inner.compressed_offset(),
                        chunk_uncompressed_offset: chunk.inner.uncompressed_offset(),
                    })
                    .context("Failed to insert chunk")?;
            }
            Ok(())
        };
        let tree = Tree::from_bootstrap(sb, &mut ())
            .context("Failed to load bootstrap for deduplication.")?;
        tree.walk_dfs_pre(process_chunk)?;
        Ok(())
    }
}

pub struct Algorithm<D: Database + Send + Sync> {
    algorithm_name: String,
    db: D,
}

// Generate deduplicated chunkdict by exponential_smoothing algorithm.
type VersionMap = HashMap<String, Vec<ChunkdictChunkInfo>>;
// Generate deduplicated chunkdict by cluster algorithm.
type ImageMap = Vec<HashMap<Vec<String>, Vec<ChunkdictChunkInfo>>>;

impl Algorithm<SqliteDatabase> {
    pub fn new(algorithm: String, db_url: &str) -> anyhow::Result<Self> {
        let algorithm_name = algorithm;
        let db = SqliteDatabase::new(db_url)?;
        Ok(Self { algorithm_name, db })
    }

    // Call the algorithm to generate a dictionary.
    pub fn chunkdict_generate(
        &mut self,
    ) -> anyhow::Result<(Vec<ChunkdictChunkInfo>, Vec<ChunkdictBlobInfo>, Vec<String>)> {
        let all_chunks: Vec<ChunkdictChunkInfo> = self.db.chunk_table.list_all()?;
        let mut chunkdict_chunks: Vec<ChunkdictChunkInfo> = Vec::new();
        let mut chunkdict_blobs: Vec<ChunkdictBlobInfo> = Vec::new();
        let mut core_image = Vec::new();
        let mut noise_points = Vec::new();

        let (chunkdict_version, chunkdict_image) = match &self.algorithm_name as &str {
            "exponential_smoothing" => Self::deduplicate_version(&all_chunks)?,
            _ => {
                bail!("Unsupported algorithm name:, please use a valid algorithm name, such as exponential_smoothing")
            }
        };
        for single_clustering in chunkdict_image {
            for (image_list, cluster_dictionary) in single_clustering {
                core_image.extend(image_list);
                chunkdict_chunks.extend(cluster_dictionary);
            }
        }
        for (_, dictionary) in chunkdict_version {
            chunkdict_chunks.extend(dictionary);
        }
        let mut chunkdict_size = 0;
        for i in &chunkdict_chunks {
            chunkdict_size += i.chunk_compressed_size;
        }
        info!(
            "Chunkdict size is {}",
            chunkdict_size as f64 / 1024_f64 / 1024_f64
        );
        for chunk in all_chunks {
            if !core_image.contains(&chunk.image_reference)
                && !noise_points.contains(&chunk.image_reference)
            {
                noise_points.push(chunk.image_reference.clone());
            }
        }
        Self::fill_chunkdict(self, &mut chunkdict_chunks, &mut chunkdict_blobs)?;
        Ok((chunkdict_chunks, chunkdict_blobs, noise_points))
    }

    /// Baseed chunk list to fill chunkdict, including all chunks in the same blob and all blobs in the chunkdict.
    fn fill_chunkdict(
        &mut self,
        chunkdict_chunks: &mut Vec<ChunkdictChunkInfo>,
        chunkdict_blobs: &mut Vec<ChunkdictBlobInfo>,
    ) -> Result<()> {
        let mut blob_ids = std::collections::HashSet::new();
        for chunk in chunkdict_chunks.iter() {
            blob_ids.insert(chunk.chunk_blob_id.clone());
        }
        for blob_id in blob_ids {
            let mut chunks = self.db.get_chunks_by_blob_id(&blob_id)?;
            chunks = chunks
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            for chunk in chunks {
                if !chunkdict_chunks.contains(&chunk) {
                    chunkdict_chunks.push(chunk);
                }
            }
            chunkdict_blobs.push(self.db.get_blob_by_id(&blob_id)?);
        }
        Ok(())
    }

    // Algorithm "exponential_smoothing"
    // List all chunk and sort them by the order in chunk table.
    // Score each chunk by "exponential_smoothing" formula.
    // Select chunks whose score is greater than threshold and generate chunk dictionary.
    fn exponential_smoothing(
        all_chunks: Vec<ChunkdictChunkInfo>,
        threshold: f64,
    ) -> anyhow::Result<Vec<ChunkdictChunkInfo>> {
        let alpha = 0.5;
        let mut smoothed_data = Vec::new();

        let mut last_start_version_index = 0;
        let mut start_version_index = 0;
        let mut last_end_version_index = 0;

        for (chunk_index, chunk) in all_chunks.iter().enumerate() {
            let mut is_duplicate: f64 = 0.0;
            if chunk.version == all_chunks[0].version {
                let smoothed_score: f64 = 0.0;
                smoothed_data.push(smoothed_score);
            } else {
                if all_chunks[chunk_index - 1].version != all_chunks[chunk_index].version {
                    last_start_version_index = start_version_index;
                    start_version_index = chunk_index;
                    last_end_version_index = chunk_index - 1;
                }
                for last_chunk in all_chunks
                    .iter()
                    .take(last_end_version_index + 1)
                    .skip(last_start_version_index)
                {
                    if chunk.chunk_digest == last_chunk.chunk_digest {
                        is_duplicate = 1.0;
                        break;
                    }
                }
                let smoothed_score: f64 =
                    alpha * is_duplicate + (1.0 - alpha) * smoothed_data[chunk_index - 1];
                smoothed_data.push(smoothed_score);
            }
        }

        let mut chunkdict: Vec<ChunkdictChunkInfo> = Vec::new();
        for i in 0..smoothed_data.len() {
            let chunk = ChunkdictChunkInfo {
                image_reference: all_chunks[i].image_reference.clone(),
                version: all_chunks[i].version.clone(),
                chunk_blob_id: all_chunks[i].chunk_blob_id.clone(),
                chunk_digest: all_chunks[i].chunk_digest.clone(),
                chunk_compressed_offset: all_chunks[i].chunk_compressed_offset,
                chunk_uncompressed_offset: all_chunks[i].chunk_uncompressed_offset,
                chunk_compressed_size: all_chunks[i].chunk_compressed_size,
                chunk_uncompressed_size: all_chunks[i].chunk_uncompressed_size,
            };
            if smoothed_data[i] > threshold {
                chunkdict.push(chunk);
            }
        }

        // Deduplicate chunk dictionary.
        let mut unique_chunks: BTreeMap<String, ChunkdictChunkInfo> = BTreeMap::new();
        for chunk in &chunkdict {
            if !unique_chunks.contains_key(&chunk.chunk_digest) {
                unique_chunks.insert(chunk.chunk_digest.clone(), chunk.clone());
            }
        }
        let unique_chunk_list: Vec<ChunkdictChunkInfo> = unique_chunks.values().cloned().collect();
        Ok(unique_chunk_list)
    }

    /// Calculate the distance between two images.
    fn distance(
        image1: &[ChunkdictChunkInfo],
        image2: &[ChunkdictChunkInfo],
    ) -> anyhow::Result<f64> {
        // The total size of all chunks in both images.
        let mut image1_size: u64 = 0;
        let mut image2_size: u64 = 0;

        for chunk1 in image1 {
            image1_size += chunk1.chunk_compressed_size as u64;
        }
        for chunk2 in image2 {
            image2_size += chunk2.chunk_compressed_size as u64;
        }

        // The total size of the chunk repeated between two images.
        let all_chunks: Vec<&ChunkdictChunkInfo> = image1.iter().chain(image2.iter()).collect();
        let mut compressed_size_map: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut processed_digests: HashSet<&String> = HashSet::new();

        for chunk in all_chunks {
            if processed_digests.contains(&chunk.chunk_digest) {
                let size = compressed_size_map
                    .entry(chunk.chunk_digest.clone())
                    .or_insert(0);
                *size += chunk.chunk_compressed_size as u64;
            }
            processed_digests.insert(&chunk.chunk_digest);
        }

        let repeat_size: u64 = compressed_size_map.values().cloned().sum();
        let distance: f64 = 1.0 - (repeat_size as f64 / ((image1_size + image2_size) as f64));
        Ok(distance)
    }

    /// Divide the chunk list into sublists by image name.
    fn divide_by_image(all_chunks: &[ChunkdictChunkInfo]) -> anyhow::Result<Vec<DataPoint>> {
        let mut image_chunks: std::collections::HashMap<String, Vec<ChunkdictChunkInfo>> =
            std::collections::HashMap::new();
        let mut datadict: Vec<DataPoint> = Vec::new();
        for chunk in all_chunks {
            image_chunks
                .entry(chunk.image_reference.clone())
                .or_default()
                .push(chunk.clone());
        }
        for (index, chunks) in image_chunks {
            let data_point = DataPoint {
                image_reference: index,
                chunk_list: chunks,
                visited: false,
                clustered: false,
                cluster_id: 0,
            };
            datadict.push(data_point);
        }
        Ok(datadict)
    }

    fn divide_set(
        chunks: &[ChunkdictChunkInfo],
        train_percentage: f64,
    ) -> anyhow::Result<(Vec<ChunkdictChunkInfo>, Vec<ChunkdictChunkInfo>)> {
        // Create a HashMap to store the list of chunks for each image_reference.
        let mut image_chunks: BTreeMap<String, Vec<ChunkdictChunkInfo>> = BTreeMap::new();

        // Group chunks into image_reference.
        for chunk in chunks {
            let entry = image_chunks
                .entry(chunk.image_reference.clone())
                .or_default();
            entry.push(chunk.clone());
        }

        // Create the final training and testing sets.
        let mut train_set: Vec<ChunkdictChunkInfo> = Vec::new();
        let mut test_set: Vec<ChunkdictChunkInfo> = Vec::new();

        // Iterate through the list of Chunks for each image_reference.
        for (_, chunk_list) in image_chunks.iter_mut() {
            let mut version_chunks: BTreeMap<CustomString, Vec<ChunkdictChunkInfo>> =
                BTreeMap::new();
            // Group the chunks in the image into version.
            for chunk in chunk_list {
                let entry = version_chunks
                    .entry(CustomString(chunk.version.clone()))
                    .or_default();
                entry.push(chunk.clone());
            }

            let num_version_groups = version_chunks.len();
            let num_train_groups = (num_version_groups as f64 * train_percentage) as usize;
            let version_groups = version_chunks.into_iter().collect::<Vec<_>>();
            let (train_version_groups, test_version_groups) =
                version_groups.split_at(num_train_groups);

            for (_, train_chunks) in train_version_groups {
                for chunk in train_chunks {
                    train_set.push(chunk.clone());
                }
            }

            for (_, test_chunks) in test_version_groups {
                for chunk in test_chunks {
                    test_set.push(chunk.clone());
                }
            }
        }
        Ok((train_set, test_set))
    }

    /// Dbscan clustering algorithm.
    fn dbsacn(data_point: &mut Vec<DataPoint>, radius: f64) -> anyhow::Result<&Vec<DataPoint>> {
        let min_points = 10;
        let mut cluster_id = 1;

        for i in 0..data_point.len() {
            if data_point[i].visited {
                continue;
            }
            if data_point[i].clustered {
                continue;
            }

            let mut neighbors = Vec::new();
            for j in 0..data_point.len() {
                let distance =
                    Self::distance(&data_point[i].chunk_list, &data_point[j].chunk_list)?;
                if !data_point[j].visited && distance <= radius {
                    neighbors.push(j);
                }
            }
            if neighbors.len() < min_points {
                data_point[i].clustered = false;
            } else {
                Self::expand_cluster(data_point, i, cluster_id, radius, min_points)?;
                cluster_id += 1;
            }
        }
        Ok(data_point)
    }

    /// Core point expansion cluster in dbscan algorithm.
    fn expand_cluster(
        data_point: &mut Vec<DataPoint>,
        i: usize,
        cluster_id: i32,
        radius: f64,
        min_points: usize,
    ) -> anyhow::Result<()> {
        data_point[i].clustered = true;
        data_point[i].cluster_id = cluster_id;

        let mut stack = vec![i];
        while let Some(q) = stack.pop() {
            if data_point[q].visited {
                continue;
            }
            data_point[q].visited = true;
            let mut q_neighbors = Vec::new();
            for j in 0..data_point.len() {
                let distance =
                    Self::distance(&data_point[q].chunk_list, &data_point[j].chunk_list)?;
                if !data_point[j].visited && distance <= radius {
                    q_neighbors.push(j);
                }
            }
            if q_neighbors.len() >= min_points {
                for &r_index in &q_neighbors {
                    if !data_point[r_index].visited {
                        data_point[r_index].visited = true;
                        stack.push(r_index)
                    }
                    if !data_point[r_index].clustered {
                        data_point[r_index].clustered = true;
                        data_point[r_index].cluster_id = cluster_id;
                    }
                }
            } else {
                data_point[i].clustered = false;
            }
        }
        Ok(())
    }

    /// Aggregate the chunks in each cluster into a dictionary.
    fn aggregate_chunk(
        data_point: &[DataPoint],
    ) -> anyhow::Result<HashMap<Vec<String>, Vec<ChunkdictChunkInfo>>> {
        // Divide chunk list according to clusters.
        let mut cluster_map: HashMap<i32, Vec<usize>> = HashMap::new();
        for (index, point) in data_point.iter().enumerate() {
            if point.clustered {
                let cluster_id = point.cluster_id;
                cluster_map.entry(cluster_id).or_default().push(index);
            }
        }

        // Iterate through each cluster.
        let mut dictionary: HashMap<Vec<String>, Vec<ChunkdictChunkInfo>> = HashMap::new();
        for (_, cluster_points) in cluster_map.iter() {
            let mut image_total_counts: HashMap<&str, usize> = HashMap::new();
            let mut image_list: Vec<String> = Vec::new();
            // Count the total number of images in the cluster.
            for &point_index in cluster_points {
                let point = &data_point[point_index];
                let image_total_count = image_total_counts
                    .entry(&point.image_reference)
                    .or_insert(0);
                *image_total_count += 1;

                image_list.push(point.image_reference.clone());
            }

            // Count the number of images in which chunks appear in the cluster.
            let mut chunk_digest_counts: HashMap<String, usize> = HashMap::new();
            for &point_index in cluster_points {
                let point = &data_point[point_index];
                let chunk_digest_set: HashSet<String> = point
                    .chunk_list
                    .iter()
                    .map(|chunk| chunk.chunk_digest.clone())
                    .collect();
                for chunk_digest in chunk_digest_set {
                    let count = chunk_digest_counts
                        .entry(chunk_digest.to_string())
                        .or_insert(0);
                    *count += 1;
                }
            }

            let mut chunk_list: Vec<ChunkdictChunkInfo> = Vec::new();
            let mut added_chunk_digests: HashSet<String> = HashSet::new();
            for &point_index in cluster_points {
                let point = &data_point[point_index];
                for chunk in &point.chunk_list {
                    let chunk_digest = &chunk.chunk_digest;
                    if !added_chunk_digests.contains(chunk_digest) {
                        let count = chunk_digest_counts.get(chunk_digest).unwrap_or(&0);
                        if *count as f64 / image_total_counts.len() as f64 >= 0.9 {
                            chunk_list.push(chunk.clone());
                            added_chunk_digests.insert(chunk_digest.to_string());
                        }
                    }
                }
            }
            dictionary.insert(image_list, chunk_list);
        }
        Ok(dictionary)
    }

    fn deduplicate_image(
        all_chunks: Vec<ChunkdictChunkInfo>,
    ) -> anyhow::Result<Vec<HashMap<Vec<String>, Vec<ChunkdictChunkInfo>>>> {
        let train_percentage = 0.7;
        let max_cluster_count = 7;
        let mut counter = 0;
        let all_chunks_clone = all_chunks;
        let mut data_dict: Vec<HashMap<Vec<String>, Vec<ChunkdictChunkInfo>>> = Vec::new();

        let (mut train, mut test) = Self::divide_set(&all_chunks_clone, train_percentage)?;
        while counter < max_cluster_count {
            // Parameter settings.
            let mut data_point = Self::divide_by_image(&train)?;
            let all_train_length = data_point.len();
            let mut radius = 0.5;
            let max_radius = 0.9;
            let mut test_chunk_sizes = Vec::new();
            let mut min_test_size: u64 = std::u64::MAX;
            let mut min_data_dict = HashMap::new();
            let mut data_cluster_length = 0;

            // Adjust the radius size to select the dictionary that tests best.
            while radius <= max_radius {
                let data_cluster = Self::dbsacn(&mut data_point, radius)?;
                data_cluster_length = data_cluster.len();

                let data_dict = Self::aggregate_chunk(data_cluster)?;

                let all_chunks: HashSet<&ChunkdictChunkInfo> =
                    data_dict.values().flat_map(|v| v.iter()).collect();
                let mut total_test_set_size: u64 = 0;

                for chunk in test.iter() {
                    if !all_chunks.contains(chunk) {
                        total_test_set_size += chunk.chunk_compressed_size as u64;
                    }
                }
                test_chunk_sizes.push((radius, total_test_set_size));
                min_test_size = total_test_set_size;
                if total_test_set_size <= min_test_size {
                    min_test_size = total_test_set_size;
                    min_data_dict = data_dict;
                }
                radius += 0.05;
            }
            debug!("test set size is {}", min_test_size);

            let min_chunk_list: Vec<ChunkdictChunkInfo> = min_data_dict
                .values()
                .flat_map(|chunk_list| chunk_list.iter())
                .cloned()
                .collect();
            let mut to_remove = Vec::new();
            for chunk in train.iter() {
                if min_chunk_list.contains(chunk) {
                    to_remove.push(chunk.clone());
                }
            }
            for chunk in &to_remove {
                train.retain(|c| c.chunk_digest != chunk.chunk_digest);
            }
            for chunk in &to_remove {
                test.retain(|c| c.chunk_digest != chunk.chunk_digest);
            }
            if (data_cluster_length as f64 / all_train_length as f64) < 0.2 {
                break;
            }
            data_dict.push(min_data_dict);
            counter += 1;
        }
        Ok(data_dict)
    }

    pub fn deduplicate_version(
        all_chunks: &[ChunkdictChunkInfo],
    ) -> anyhow::Result<(VersionMap, ImageMap)> {
        let mut all_chunks_size = 0;
        for i in all_chunks {
            all_chunks_size += i.chunk_compressed_size;
        }
        info!(
            "All chunk size is {}",
            all_chunks_size as f64 / 1024_f64 / 1024_f64
        );

        let train_percentage = 0.7;
        let datadict = Self::deduplicate_image(all_chunks.to_owned())?;
        let (train, test) = Self::divide_set(all_chunks, train_percentage)?;
        let mut train_set_size = 0;
        for i in &train {
            train_set_size += i.chunk_compressed_size;
        }
        info!(
            "Train set size is {}",
            train_set_size as f64 / 1024_f64 / 1024_f64
        );

        let mut test_set_size = 0;
        for i in &test {
            test_set_size += i.chunk_compressed_size;
        }
        info!(
            "Test set size is {}",
            test_set_size as f64 / 1024_f64 / 1024_f64
        );

        let mut version_datadict: HashMap<String, Vec<ChunkdictChunkInfo>> = HashMap::new();
        let mut data_point = Self::divide_by_image(&train)?;

        let mut threshold = 0.5;
        let max_threshold = 0.8;

        let mut test_total_size: u32 = 0;
        let mut min_test_size: u32 = std::u32::MAX;
        let mut min_data_dict = HashMap::new();

        while threshold <= max_threshold {
            version_datadict.clear();
            for point in data_point.iter_mut() {
                for single_dictionary in &datadict {
                    for (key, value) in single_dictionary.iter() {
                        if key.contains(&point.image_reference) {
                            let mut to_remove = Vec::new();
                            for chunk in point.chunk_list.iter() {
                                if value.contains(chunk) {
                                    to_remove.push(chunk.clone());
                                }
                            }
                            for chunk in to_remove {
                                point.chunk_list.retain(|c| c != &chunk);
                            }
                        }
                    }
                }
                let chunk_dict = Self::exponential_smoothing(point.chunk_list.clone(), threshold)?;
                version_datadict.insert(point.image_reference.clone(), chunk_dict);
            }

            let mut test_by_image = Self::divide_by_image(&test)?;
            for point in test_by_image.iter_mut() {
                if version_datadict.contains_key(&point.image_reference.clone()) {
                    let mut to_remove = Vec::new();
                    let mut vec_string = Vec::new();
                    let chunkdict_option = version_datadict.get(&point.image_reference);
                    if let Some(chunkdict) = chunkdict_option {
                        for i in chunkdict {
                            vec_string.push(i.chunk_digest.clone());
                        }
                    }
                    for chunk in point.chunk_list.iter() {
                        if vec_string.contains(&chunk.chunk_digest) {
                            to_remove.push(chunk.clone());
                        }
                    }
                    for chunk in to_remove {
                        point.chunk_list.retain(|c| c != &chunk);
                    }
                }
                for chunk in point.chunk_list.iter() {
                    test_total_size = test_total_size
                        .checked_add(chunk.chunk_compressed_size)
                        .unwrap_or(test_total_size);
                }
            }
            if test_total_size <= min_test_size {
                min_test_size = test_total_size;
                min_data_dict = version_datadict.clone();
            }
            threshold += 0.05;
        }
        info!(
            "After deduplicating test set size is {} and deduplicating rate is {} ",
            min_test_size as f64 / 1024_f64 / 1024_f64,
            1.0 - (min_test_size as f64) / (test_set_size as f64)
        );
        Ok((min_data_dict, datadict))
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct DataPoint {
    image_reference: String,
    chunk_list: Vec<ChunkdictChunkInfo>,
    visited: bool,
    clustered: bool,
    cluster_id: i32,
}

pub trait Table<T, Err>: Sync + Send + Sized + 'static
where
    Err: std::error::Error + 'static,
{
    /// Clear table.
    fn clear(&self) -> Result<(), Err>;

    /// Create table.
    fn create(&self) -> Result<(), Err>;

    /// Insert data.
    fn insert(&self, table: &T) -> Result<(), Err>;

    /// Select all data.
    fn list_all(&self) -> Result<Vec<T>, Err>;

    /// Select data with offset and limit.
    fn list_paged(&self, offset: i64, limit: i64) -> Result<Vec<T>, Err>;
}

#[derive()]
pub struct ChunkTable {
    conn: Arc<Mutex<Connection>>,
}

impl ChunkTable {
    pub fn new(database_url: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(database_url)?;
        Ok(ChunkTable {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn new_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        Ok(ChunkTable {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Select all data filtered by blob ID.
    fn list_all_by_blob_id(&self, blob_id: &str) -> Result<Vec<ChunkdictChunkInfo>, DatabaseError> {
        let mut offset = 0;
        let limit: i64 = 100;
        let mut all_chunks_by_blob_id = Vec::new();

        loop {
            let chunks = self.list_paged_by_blob_id(blob_id, offset, limit)?;
            if chunks.is_empty() {
                break;
            }

            all_chunks_by_blob_id.extend(chunks);
            offset += limit;
        }

        Ok(all_chunks_by_blob_id)
    }

    /// Select data with offset and limit filtered by blob ID.
    fn list_paged_by_blob_id(
        &self,
        blob_id: &str,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<ChunkdictChunkInfo>, DatabaseError> {
        let conn_guard = self
            .conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?;
        let mut stmt: rusqlite::Statement<'_> = conn_guard
            .prepare(
                "SELECT id, image_reference, version, chunk_blob_id, chunk_digest, chunk_compressed_size,
                chunk_uncompressed_size, chunk_compressed_offset, chunk_uncompressed_offset from chunk
                WHERE chunk_blob_id = ?1
                ORDER BY id LIMIT ?2 OFFSET ?3",
            )?;
        let chunk_iterator = stmt.query_map(params![blob_id, limit, offset], |row| {
            Ok(ChunkdictChunkInfo {
                image_reference: row.get(1)?,
                version: row.get(2)?,
                chunk_blob_id: row.get(3)?,
                chunk_digest: row.get(4)?,
                chunk_compressed_size: row.get(5)?,
                chunk_uncompressed_size: row.get(6)?,
                chunk_compressed_offset: row.get(7)?,
                chunk_uncompressed_offset: row.get(8)?,
            })
        })?;
        let mut chunks = Vec::new();
        for chunk in chunk_iterator {
            chunks.push(chunk.map_err(DatabaseError::SqliteError)?);
        }
        Ok(chunks)
    }
}

#[derive(Debug, Clone)]
struct CustomString(String);

impl Ord for CustomString {
    /// Extract the numbers in the string.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let mut current_number = String::new();

        // Parse numbers in strings.
        let mut numbers1 = Vec::new();
        let mut numbers2 = Vec::new();

        for ch in self.0.chars() {
            if ch.is_ascii_digit() {
                current_number.push(ch);
            } else if !current_number.is_empty() {
                if let Ok(number) = current_number.parse::<i32>() {
                    numbers1.push(number);
                }
                current_number.clear();
            }
        }
        if !current_number.is_empty() {
            if let Ok(number) = current_number.parse::<i32>() {
                numbers1.push(number);
            }
        }
        current_number.clear();

        for ch in other.0.chars() {
            if ch.is_ascii_digit() {
                current_number.push(ch);
            } else if !current_number.is_empty() {
                if let Ok(number) = current_number.parse::<i32>() {
                    numbers2.push(number);
                }
                current_number.clear();
            }
        }
        if !current_number.is_empty() {
            if let Ok(number) = current_number.parse::<i32>() {
                numbers2.push(number);
            }
        }
        current_number.clear();
        numbers1.cmp(&numbers2)
    }
}

impl PartialOrd for CustomString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for CustomString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for CustomString {}

impl Table<ChunkdictChunkInfo, DatabaseError> for ChunkTable {
    fn clear(&self) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute("DROP TABLE chunk", [])
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn create(&self) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute(
                "CREATE TABLE IF NOT EXISTS chunk (
                    id               INTEGER PRIMARY KEY,
                    image_reference  TEXT,
                    version          TEXT,
                    chunk_blob_id    TEXT NOT NULL,
                    chunk_digest     TEXT,
                    chunk_compressed_size  INT,
                    chunk_uncompressed_size  INT,
                    chunk_compressed_offset  INT,
                    chunk_uncompressed_offset  INT
                )",
                [],
            )
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn insert(&self, chunk: &ChunkdictChunkInfo) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute(
                "INSERT INTO chunk(
                    image_reference,
                    version,
                    chunk_blob_id,
                    chunk_digest,
                    chunk_compressed_size,
                    chunk_uncompressed_size,
                    chunk_compressed_offset,
                    chunk_uncompressed_offset
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);
                ",
                rusqlite::params![
                    chunk.image_reference,
                    chunk.version,
                    chunk.chunk_blob_id,
                    chunk.chunk_digest,
                    chunk.chunk_compressed_size,
                    chunk.chunk_uncompressed_size,
                    chunk.chunk_compressed_offset,
                    chunk.chunk_uncompressed_offset,
                ],
            )
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn list_all(&self) -> Result<Vec<ChunkdictChunkInfo>, DatabaseError> {
        let mut offset = 0;
        let limit: i64 = 100;
        let mut all_chunks = Vec::new();

        loop {
            let chunks = self.list_paged(offset, limit)?;
            if chunks.is_empty() {
                break;
            }

            all_chunks.extend(chunks);
            offset += limit;
        }

        Ok(all_chunks)
    }

    fn list_paged(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<ChunkdictChunkInfo>, DatabaseError> {
        let conn_guard = self
            .conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?;
        let mut stmt: rusqlite::Statement<'_> = conn_guard
            .prepare(
                "SELECT id, image_reference, version, chunk_blob_id, chunk_digest, chunk_compressed_size,
                chunk_uncompressed_size, chunk_compressed_offset, chunk_uncompressed_offset from chunk
                ORDER BY id LIMIT ?1 OFFSET ?2",
            )?;
        let chunk_iterator = stmt.query_map(params![limit, offset], |row| {
            Ok(ChunkdictChunkInfo {
                image_reference: row.get(1)?,
                version: row.get(2)?,
                chunk_blob_id: row.get(3)?,
                chunk_digest: row.get(4)?,
                chunk_compressed_size: row.get(5)?,
                chunk_uncompressed_size: row.get(6)?,
                chunk_compressed_offset: row.get(7)?,
                chunk_uncompressed_offset: row.get(8)?,
            })
        })?;
        let mut chunks = Vec::new();
        for chunk in chunk_iterator {
            chunks.push(chunk.map_err(DatabaseError::SqliteError)?);
        }
        Ok(chunks)
    }
}

#[derive(Debug)]
pub struct BlobTable {
    conn: Arc<Mutex<Connection>>,
}

impl BlobTable {
    pub fn new(database_url: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(database_url)?;
        Ok(BlobTable {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn new_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        Ok(BlobTable {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn list_by_id(&self, blob_id: &str) -> Result<ChunkdictBlobInfo, DatabaseError> {
        let conn_guard = self
            .conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?;
        let mut stmt = conn_guard.prepare(
            "SELECT blob_id, blob_compressed_size, blob_uncompressed_size, blob_compressor, blob_meta_ci_compressed_size, blob_meta_ci_uncompressed_size, blob_meta_ci_offset FROM blob WHERE blob_id = ?1",
        )?;
        let mut blob_iterator = stmt.query_map([blob_id], |row| {
            Ok(ChunkdictBlobInfo {
                blob_id: row.get(0)?,
                blob_compressed_size: row.get(1)?,
                blob_uncompressed_size: row.get(2)?,
                blob_compressor: row.get(3)?,
                blob_meta_ci_compressed_size: row.get(4)?,
                blob_meta_ci_uncompressed_size: row.get(5)?,
                blob_meta_ci_offset: row.get(6)?,
            })
        })?;

        if let Some(blob) = blob_iterator.next() {
            blob.map_err(DatabaseError::SqliteError)
        } else {
            Err(DatabaseError::SqliteError(
                rusqlite::Error::QueryReturnedNoRows,
            ))
        }
    }
}

impl Table<ChunkdictBlobInfo, DatabaseError> for BlobTable {
    fn clear(&self) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute("DROP TABLE blob", [])
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn create(&self) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute(
                "CREATE TABLE IF NOT EXISTS blob (
                    id                                  INTEGER PRIMARY KEY,
                    blob_id                             TEXT NOT NULL,
                    blob_compressed_size                INT,
                    blob_uncompressed_size              INT,
                    blob_compressor                     TEXT,
                    blob_meta_ci_compressed_size        INT,
                    blob_meta_ci_uncompressed_size      INT,
                    blob_meta_ci_offset                 INT
                )",
                [],
            )
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn insert(&self, blob: &ChunkdictBlobInfo) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute(
                "INSERT INTO blob (
                    blob_id,
                    blob_compressed_size,
                    blob_uncompressed_size,
                    blob_compressor,
                    blob_meta_ci_compressed_size,
                    blob_meta_ci_uncompressed_size,
                    blob_meta_ci_offset
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
                ",
                rusqlite::params![
                    blob.blob_id,
                    blob.blob_compressed_size,
                    blob.blob_uncompressed_size,
                    blob.blob_compressor,
                    blob.blob_meta_ci_compressed_size,
                    blob.blob_meta_ci_uncompressed_size,
                    blob.blob_meta_ci_offset,
                ],
            )
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn list_all(&self) -> Result<Vec<ChunkdictBlobInfo>, DatabaseError> {
        let mut offset = 0;
        let limit: i64 = 100;
        let mut all_blobs = Vec::new();

        loop {
            let blobs = self.list_paged(offset, limit)?;
            if blobs.is_empty() {
                break;
            }

            all_blobs.extend(blobs);
            offset += limit;
        }

        Ok(all_blobs)
    }

    fn list_paged(&self, offset: i64, limit: i64) -> Result<Vec<ChunkdictBlobInfo>, DatabaseError> {
        let conn_guard = self
            .conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?;
        let mut stmt: rusqlite::Statement<'_> = conn_guard.prepare(
            "SELECT blob_id, blob_compressed_size, blob_uncompressed_size, blob_compressor, blob_meta_ci_compressed_size, blob_meta_ci_uncompressed_size, blob_meta_ci_offset from blob
                ORDER BY id LIMIT ?1 OFFSET ?2",
        )?;
        let blob_iterator = stmt.query_map(params![limit, offset], |row| {
            Ok(ChunkdictBlobInfo {
                blob_id: row.get(0)?,
                blob_compressed_size: row.get(1)?,
                blob_uncompressed_size: row.get(2)?,
                blob_compressor: row.get(3)?,
                blob_meta_ci_compressed_size: row.get(4)?,
                blob_meta_ci_uncompressed_size: row.get(5)?,
                blob_meta_ci_offset: row.get(6)?,
            })
        })?;
        let mut blobs = Vec::new();
        for blob in blob_iterator {
            blobs.push(blob.map_err(DatabaseError::SqliteError)?);
        }
        Ok(blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Result;

    #[test]
    fn test_partial_cmp() -> Result<(), Box<dyn std::error::Error>> {
        let custom_string1 = CustomString("nydus_1.2.3".to_string());
        let custom_string2 = CustomString("nydus_1.2.10".to_string());
        let custom_string3 = CustomString("nydus_2.0".to_string());

        assert!(custom_string1 < custom_string2);
        assert!(custom_string2 < custom_string3);
        assert!(custom_string1 < custom_string3);

        assert!(custom_string1 <= custom_string2);
        assert!(custom_string2 <= custom_string3);
        assert!(custom_string1 <= custom_string3);

        assert!(custom_string2 > custom_string1);
        assert!(custom_string3 > custom_string2);
        assert!(custom_string3 > custom_string1);

        assert!(custom_string2 >= custom_string1);
        assert!(custom_string3 >= custom_string2);
        assert!(custom_string3 >= custom_string1);

        assert_eq!(custom_string1, CustomString("nydus_1.2.3".to_string()));
        assert_ne!(custom_string1, custom_string2);
        Ok(())
    }

    #[test]
    fn test_blob_table() -> Result<(), Box<dyn std::error::Error>> {
        let blob_table = BlobTable::new_in_memory()?;
        blob_table.create()?;
        let blob = ChunkdictBlobInfo {
            blob_id: "BLOB123".to_string(),
            blob_compressed_size: 1024,
            blob_uncompressed_size: 2048,
            blob_compressor: "zstd".to_string(),
            blob_meta_ci_compressed_size: 1024,
            blob_meta_ci_uncompressed_size: 2048,
            blob_meta_ci_offset: 0,
        };
        blob_table.insert(&blob)?;
        let blobs = blob_table.list_all()?;
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].blob_id, blob.blob_id);
        assert_eq!(blobs[0].blob_compressed_size, blob.blob_compressed_size);
        assert_eq!(blobs[0].blob_uncompressed_size, blob.blob_uncompressed_size);
        assert_eq!(blobs[0].blob_compressor, blob.blob_compressor);
        assert_eq!(
            blobs[0].blob_meta_ci_compressed_size,
            blob.blob_meta_ci_compressed_size
        );
        assert_eq!(
            blobs[0].blob_meta_ci_uncompressed_size,
            blob.blob_meta_ci_uncompressed_size
        );
        assert_eq!(blobs[0].blob_meta_ci_offset, blob.blob_meta_ci_offset);
        Ok(())
    }

    #[test]
    fn test_chunk_table() -> Result<(), Box<dyn std::error::Error>> {
        let chunk_table = ChunkTable::new_in_memory()?;
        chunk_table.create()?;
        let chunk = ChunkdictChunkInfo {
            image_reference: "REDIS".to_string(),
            version: "1.0.0".to_string(),
            chunk_blob_id: "BLOB123".to_string(),
            chunk_digest: "DIGEST123".to_string(),
            chunk_compressed_size: 512,
            chunk_uncompressed_size: 1024,
            chunk_compressed_offset: 0,
            chunk_uncompressed_offset: 0,
        };
        chunk_table.insert(&chunk)?;
        let chunk2 = ChunkdictChunkInfo {
            image_reference: "REDIS02".to_string(),
            version: "1.0.0".to_string(),
            chunk_blob_id: "BLOB456".to_string(),
            chunk_digest: "DIGEST123".to_string(),
            chunk_compressed_size: 512,
            chunk_uncompressed_size: 1024,
            chunk_compressed_offset: 0,
            chunk_uncompressed_offset: 0,
        };
        chunk_table.insert(&chunk2)?;
        let chunks = chunk_table.list_all()?;
        assert_eq!(chunks[0].image_reference, chunk.image_reference);
        assert_eq!(chunks[0].version, chunk.version);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].chunk_blob_id, chunk.chunk_blob_id);
        assert_eq!(chunks[0].chunk_digest, chunk.chunk_digest);
        assert_eq!(chunks[0].chunk_compressed_size, chunk.chunk_compressed_size);
        assert_eq!(
            chunks[0].chunk_uncompressed_size,
            chunk.chunk_uncompressed_size
        );
        assert_eq!(
            chunks[0].chunk_compressed_offset,
            chunk.chunk_compressed_offset
        );
        assert_eq!(
            chunks[0].chunk_uncompressed_offset,
            chunk.chunk_uncompressed_offset
        );

        let chunks = chunk_table.list_all_by_blob_id(&chunk.chunk_blob_id)?;
        assert_eq!(chunks[0].chunk_blob_id, chunk.chunk_blob_id);
        assert_eq!(chunks.len(), 1);

        Ok(())
    }

    #[test]
    fn test_blob_table_paged() -> Result<(), Box<dyn std::error::Error>> {
        let blob_table = BlobTable::new_in_memory()?;
        blob_table.create()?;
        for i in 0..200 {
            let blob = ChunkdictBlobInfo {
                blob_id: format!("BLOB{}", i),
                blob_compressed_size: i,
                blob_uncompressed_size: i * 2,
                blob_compressor: "zstd".to_string(),
                blob_meta_ci_compressed_size: i,
                blob_meta_ci_uncompressed_size: i * 2,
                blob_meta_ci_offset: i * 3,
            };
            blob_table.insert(&blob)?;
        }
        let blobs = blob_table.list_paged(100, 100)?;
        assert_eq!(blobs.len(), 100);
        assert_eq!(blobs[0].blob_id, "BLOB100");
        assert_eq!(blobs[0].blob_compressed_size, 100);
        assert_eq!(blobs[0].blob_uncompressed_size, 200);
        assert_eq!(blobs[0].blob_compressor, "zstd");
        assert_eq!(blobs[0].blob_meta_ci_compressed_size, 100);
        assert_eq!(blobs[0].blob_meta_ci_uncompressed_size, 200);
        assert_eq!(blobs[0].blob_meta_ci_offset, 300);
        Ok(())
    }

    #[test]
    fn test_chunk_table_paged() -> Result<(), Box<dyn std::error::Error>> {
        let chunk_table = ChunkTable::new_in_memory()?;
        chunk_table.create()?;
        for i in 0..200 {
            let i64 = i as u64;
            let chunk = ChunkdictChunkInfo {
                image_reference: format!("REDIS{}", i),
                version: format!("1.0.0{}", i),
                chunk_blob_id: format!("BLOB{}", i),
                chunk_digest: format!("DIGEST{}", i),
                chunk_compressed_size: i,
                chunk_uncompressed_size: i * 2,
                chunk_compressed_offset: i64 * 3,
                chunk_uncompressed_offset: i64 * 4,
            };
            chunk_table.insert(&chunk)?;
        }
        let chunks = chunk_table.list_paged(100, 100)?;
        assert_eq!(chunks.len(), 100);
        assert_eq!(chunks[0].image_reference, "REDIS100");
        assert_eq!(chunks[0].version, "1.0.0100");
        assert_eq!(chunks[0].chunk_blob_id, "BLOB100");
        assert_eq!(chunks[0].chunk_digest, "DIGEST100");
        assert_eq!(chunks[0].chunk_compressed_size, 100);
        assert_eq!(chunks[0].chunk_uncompressed_size, 200);
        assert_eq!(chunks[0].chunk_compressed_offset, 300);
        assert_eq!(chunks[0].chunk_uncompressed_offset, 400);
        Ok(())
    }

    #[test]
    fn test_algorithm_exponential_smoothing() -> Result<(), Box<dyn std::error::Error>> {
        let threshold = 0.1;
        let mut all_chunk: Vec<ChunkdictChunkInfo> = Vec::new();
        for i in 0..199 {
            let i64 = i as u64;
            let chunk = ChunkdictChunkInfo {
                image_reference: format!("REDIS{}", 0),
                version: format!("1.0.0{}", (i + 1) / 100),
                chunk_blob_id: format!("BLOB{}", i),
                chunk_digest: format!("DIGEST{}", (i + 1) % 2),
                chunk_compressed_size: i,
                chunk_uncompressed_size: i * 2,
                chunk_compressed_offset: i64 * 3,
                chunk_uncompressed_offset: i64 * 4,
            };
            all_chunk.push(chunk);
        }
        let chunkdict = Algorithm::<SqliteDatabase>::exponential_smoothing(all_chunk, threshold)?;
        assert_eq!(chunkdict.len(), 2);
        assert_eq!(chunkdict[0].image_reference, "REDIS0");
        assert_eq!(chunkdict[0].version, "1.0.01");
        assert_eq!(chunkdict[0].chunk_blob_id, "BLOB99");
        assert_eq!(chunkdict[0].chunk_digest, "DIGEST0");
        assert_eq!(chunkdict[0].chunk_compressed_size, 99);
        assert_eq!(chunkdict[0].chunk_uncompressed_size, 198);
        assert_eq!(chunkdict[0].chunk_compressed_offset, 297);
        assert_eq!(chunkdict[0].chunk_uncompressed_offset, 396);
        Ok(())
    }

    #[test]
    fn test_divide_by_image() -> Result<(), Box<dyn std::error::Error>> {
        let db_url = "./metadata.db";
        let chunk_table = ChunkTable::new(db_url)?;
        chunk_table.create()?;
        for i in 0..200 {
            let i64 = i as u64;
            let chunk = ChunkdictChunkInfo {
                image_reference: format!("REDIS{}", i / 50),
                version: format!("1.0.0{}", (i + 1) / 100),
                chunk_blob_id: format!("BLOB{}", i),
                chunk_digest: format!("DIGEST{}", (i + 1) % 2),
                chunk_compressed_size: i,
                chunk_uncompressed_size: i * 2,
                chunk_compressed_offset: i64 * 3,
                chunk_uncompressed_offset: i64 * 4,
            };
            chunk_table.insert(&chunk)?;
        }
        let algorithm = String::from("exponential_smoothing");
        let algorithm = Algorithm::<SqliteDatabase>::new(algorithm, db_url)?;
        let all_chunks = algorithm.db.chunk_table.list_all()?;
        assert_eq!(all_chunks.len(), 200);
        let datadict = Algorithm::<SqliteDatabase>::divide_by_image(&all_chunks)?;
        assert_eq!(datadict.len(), 4);
        assert_eq!(datadict[3].cluster_id, 0);
        assert_eq!(datadict[3].chunk_list.len(), 50);
        chunk_table.clear()?;
        Ok(())
    }

    #[test]
    fn test_distance() -> Result<(), Box<dyn std::error::Error>> {
        let mut all_chunks1: Vec<ChunkdictChunkInfo> = Vec::new();
        for i in 0..200 {
            let i64 = i as u64;
            let chunk = ChunkdictChunkInfo {
                image_reference: format!("REDIS{}", 0),
                version: format!("1.0.0{}", (i + 1) / 100),
                chunk_blob_id: format!("BLOB{}", i),
                chunk_digest: format!("DIGEST{}", (i + 1) % 4),
                chunk_compressed_size: 1,
                chunk_uncompressed_size: 1,
                chunk_compressed_offset: i64 * 3,
                chunk_uncompressed_offset: i64 * 4,
            };
            all_chunks1.push(chunk);
        }
        let mut all_chunks2: Vec<ChunkdictChunkInfo> = Vec::new();
        for i in 0..200 {
            let i64 = i as u64;
            let chunk = ChunkdictChunkInfo {
                image_reference: format!("REDIS{}", 1),
                version: format!("1.0.0{}", (i + 1) / 100),
                chunk_blob_id: format!("BLOB{}", i),
                chunk_digest: format!("DIGEST{}", (i + 1) % 4),
                chunk_compressed_size: 1,
                chunk_uncompressed_size: 1,
                chunk_compressed_offset: i64 * 3,
                chunk_uncompressed_offset: i64 * 4,
            };
            all_chunks2.push(chunk);
        }
        let datadict = Algorithm::<SqliteDatabase>::distance(&all_chunks1, &all_chunks2)?;
        assert!(
            (datadict - 0.01).abs() <= 0.0001,
            "Expected {} to be approximately equal to {} with tolerance {}",
            datadict,
            0.01,
            0.0001
        );
        Ok(())
    }

    #[test]
    fn test_divide_set() -> Result<(), Box<dyn std::error::Error>> {
        let mut all_chunks: Vec<ChunkdictChunkInfo> = Vec::new();
        for i in 0..200 {
            for j in 0..100 {
                let chunk = ChunkdictChunkInfo {
                    image_reference: format!("REDIS{}", i),
                    version: format!("1.0.0{}", j / 10),
                    chunk_blob_id: format!("BLOB{}", j),
                    chunk_digest: format!("DIGEST{}", j + (i / 100) * 100),
                    chunk_compressed_size: 1,
                    chunk_uncompressed_size: 1,
                    chunk_compressed_offset: 1,
                    chunk_uncompressed_offset: 1,
                };
                all_chunks.push(chunk);
            }
        }
        assert_eq!(all_chunks.len(), 20000);
        let (train, test) = Algorithm::<SqliteDatabase>::divide_set(&all_chunks, 0.7)?;
        assert_eq!(train.len(), 14000);
        assert_eq!(train[0].image_reference, "REDIS0");
        assert_eq!(train[0].version, "1.0.00");
        assert_eq!(test.len(), 6000);
        assert_eq!(test[0].image_reference, "REDIS0");
        assert_eq!(test[0].version, "1.0.07");
        Ok(())
    }

    #[test]
    fn test_dbscan() -> Result<(), Box<dyn std::error::Error>> {
        let mut all_chunks: Vec<ChunkdictChunkInfo> = Vec::new();
        let radius = 0.6;
        for i in 0..200 {
            for j in 0..100 {
                let chunk = ChunkdictChunkInfo {
                    image_reference: format!("REDIS{}", i),
                    version: format!("1.0.0{}", j / 10),
                    chunk_blob_id: format!("BLOB{}", j),
                    chunk_digest: format!("DIGEST{}", j + (i / 100) * 100),
                    chunk_compressed_size: 1,
                    chunk_uncompressed_size: 1,
                    chunk_compressed_offset: 1,
                    chunk_uncompressed_offset: 1,
                };
                all_chunks.push(chunk);
            }
        }
        assert_eq!(all_chunks.len(), 20000);
        let mut data_point = Algorithm::<SqliteDatabase>::divide_by_image(&all_chunks)?;
        let datadict = Algorithm::<SqliteDatabase>::dbsacn(&mut data_point, radius)?;
        assert_eq!(datadict.len(), 200);
        if datadict[150].chunk_list[0].chunk_digest == datadict[0].chunk_list[0].chunk_digest {
            assert_eq!(datadict[150].cluster_id, 1);
        } else {
            assert_eq!(datadict[150].cluster_id, 2);
        }
        assert_eq!(datadict[0].cluster_id, 1);
        assert!(datadict[150].clustered);
        assert!(datadict[150].visited);
        assert_eq!(datadict[0].chunk_list.len(), 100);
        Ok(())
    }

    #[test]
    fn test_aggregate_chunk() -> Result<(), Box<dyn std::error::Error>> {
        let mut all_chunks: Vec<ChunkdictChunkInfo> = Vec::new();
        let radius = 0.6;
        for i in 0..200 {
            for j in 0..100 {
                let chunk = ChunkdictChunkInfo {
                    image_reference: format!("REDIS{}", i),
                    version: format!("1.0.0{}", (j + 1) / 100),
                    chunk_blob_id: format!("BLOB{}", j),
                    chunk_digest: format!("DIGEST{}", j + (i / 100) * 100),
                    chunk_compressed_size: 1,
                    chunk_uncompressed_size: 1,
                    chunk_compressed_offset: 1,
                    chunk_uncompressed_offset: 1,
                };
                all_chunks.push(chunk);
            }
        }
        assert_eq!(all_chunks.len(), 20000);
        let mut data_point = Algorithm::<SqliteDatabase>::divide_by_image(&all_chunks)?;
        let data_cluster = Algorithm::<SqliteDatabase>::dbsacn(&mut data_point, radius)?;
        let datadict = Algorithm::<SqliteDatabase>::aggregate_chunk(&data_cluster)?;
        assert_eq!(datadict.len(), 2);
        Ok(())
    }

    #[test]
    fn test_deduplicate_image() -> Result<(), Box<dyn std::error::Error>> {
        let mut all_chunks: Vec<ChunkdictChunkInfo> = Vec::new();
        for i in 0..200 {
            for j in 0..100 {
                let chunk = ChunkdictChunkInfo {
                    image_reference: format!("REDIS{}", i),
                    version: format!("1.0.0{}", j / 10),
                    chunk_blob_id: format!("BLOB{}", j),
                    chunk_digest: format!("DIGEST{}", j + (i / 100) * 100),
                    chunk_compressed_size: 1,
                    chunk_uncompressed_size: 1,
                    chunk_compressed_offset: 1,
                    chunk_uncompressed_offset: 1,
                };
                all_chunks.push(chunk);
            }
        }
        assert_eq!(all_chunks.len(), 20000);
        let datadict = Algorithm::<SqliteDatabase>::deduplicate_image(all_chunks)?;
        for i in datadict.clone() {
            for (_, b) in i {
                if !b.is_empty() {
                    assert_eq!(b.len(), 70);
                }
            }
        }
        assert_eq!(datadict[0].len(), 2);
        assert_eq!(datadict[0].values().len(), 2);
        assert_eq!(datadict[1].len(), 0);
        assert_eq!(datadict[1].values().len(), 0);
        assert_eq!(datadict.len(), 7);
        Ok(())
    }

    #[test]
    fn test_deduplicate_version() -> Result<(), Box<dyn std::error::Error>> {
        let mut all_chunks: Vec<ChunkdictChunkInfo> = Vec::new();
        let mut chunkdict: Vec<ChunkdictChunkInfo> = Vec::new();
        for i in 0..200 {
            let i64 = i as u64;
            let chunk = ChunkdictChunkInfo {
                image_reference: format!("REDIS{}", 0),
                version: format!("1.0.0{}", (i + 1) / 20),
                chunk_blob_id: format!("BLOB{}", i),
                chunk_digest: format!("DIGEST{}", (i + 1) % 2),
                chunk_compressed_size: i,
                chunk_uncompressed_size: i * 2,
                chunk_compressed_offset: i64 * 3,
                chunk_uncompressed_offset: i64 * 4,
            };
            all_chunks.push(chunk);
        }
        let (chunkdict_version, chunkdict_image) =
            Algorithm::<SqliteDatabase>::deduplicate_version(&all_chunks)?;
        for (_, dictionary) in chunkdict_version {
            chunkdict.extend(dictionary);
        }

        assert_eq!(chunkdict[0].image_reference, "REDIS0");
        assert_eq!(chunkdict[0].chunk_compressed_size, 21);
        assert_eq!(chunkdict.len(), 2);

        for single_clustering in chunkdict_image {
            for (_, cluster_dictionary) in single_clustering {
                chunkdict.extend(cluster_dictionary);
            }
        }
        assert_eq!(chunkdict.len(), 2);
        Ok(())
    }
}
