use nydus_utils::exec;
use serde_json::Value::{self, Null};
use std::{fs::File, io::Read};

pub fn test_image_inspect_cmd(cmd: &str, bootstrap_path: &str) {
    let nydus_image = std::env::var("NYDUS_IMAGE")
        .unwrap_or_else(|_| String::from("./target-fusedev/release/nydus-image"));

    let output = exec(
        format!("{} inspect -B {} -R {}", nydus_image, bootstrap_path, cmd).as_str(),
        true,
        b"",
    )
    .unwrap();
    let mut expected = String::new();

    let mut texture = File::open(format!("./tests/texture/image-inspect/{}.result", cmd)).unwrap();
    texture.read_to_string(&mut expected).unwrap();
    is_right(cmd, output, expected);
}

fn is_right(cmd: &str, output: String, expected: String) {
    match cmd {
        "stats" => is_right_stats(output, expected),
        "prefetch" => is_right_prefetch(output, expected),
        "blobs" => is_right_blobs(output, expected),
        _ => println!("This cmd is not supported now!"),
    }
}

fn is_right_stats(output: String, expected: String) {
    let output_value: Value = serde_json::from_str(output.as_str()).unwrap();
    let expected_value: Value = serde_json::from_str(expected.as_str()).unwrap();
    assert_eq!(
        output_value["inodes_count".to_string()],
        expected_value["inodes_count".to_string()]
    );
}

fn is_right_prefetch(output: String, expected: String) {
    let output_value: Vec<Value> = serde_json::from_str(output.as_str()).unwrap();
    let expected_value: Vec<Value> = serde_json::from_str(expected.as_str()).unwrap();

    assert_eq!(output_value.len(), expected_value.len());
    for index in 0..expected_value.len() {
        let expected_v = expected_value.get(index).unwrap();
        let mut matched = false;
        for output_v in output_value.iter() {
            if output_v["inode"] == expected_v["inode"] {
                assert_eq!(output_v["path"], expected_v["path"]);
                matched = true;
                break;
            }
        }
        assert!(matched);
    }
}

fn is_right_blobs(output: String, expected: String) {
    let output_value: Vec<Value> = serde_json::from_str(output.as_str()).unwrap();
    let expected_value: Vec<Value> = serde_json::from_str(expected.as_str()).unwrap();

    assert_eq!(output_value.len(), expected_value.len());
    for index in 0..expected_value.len() {
        let expected_v = expected_value.get(index).unwrap();
        let mut matched = false;
        for output_v in output_value.iter() {
            if output_v["blob_id"] == expected_v["blob_id"] {
                if expected_v["compressed_size"] == Null {
                    assert_eq!(0_i32, output_v["compressed_size"]);
                } else {
                    assert_eq!(expected_v["compressed_size"], output_v["compressed_size"])
                }

                if expected_v["decompressed_size"] == Null {
                    assert_eq!(0_i32, output_v["decompressed_size"]);
                } else {
                    assert_eq!(
                        expected_v["decompressed_size"],
                        output_v["decompressed_size"]
                    );
                }

                assert_eq!(expected_v["readahead_offset"], output_v["readahead_offset"]);
                assert_eq!(expected_v["readahead_size"], output_v["readahead_size"]);

                matched = true;
                break;
            }
        }

        assert!(matched);
    }
}
