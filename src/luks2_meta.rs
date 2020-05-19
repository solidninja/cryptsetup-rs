//! LUKS2 JSON metadata parsing

use std::collections::HashMap;
use std::convert::TryFrom;
use std::error;

use base64::STANDARD;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::skip_serializing_none;

base64_serde_type!(Base64Standard, STANDARD);

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum Luks2ConfigFlag {
    AllowDiscards,
    SameCpuCrypt,
    SubmitFromCryptCpus,
    NoJournal,
    #[serde(other, skip_serializing)]
    Unknown,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2Config {
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub json_size: u64,
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub keyslots_size: u64,
    pub flags: Option<Vec<Luks2ConfigFlag>>,
    pub requirements: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Luks2DigestType {
    Pbkdf2,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2Digest {
    #[serde(rename = "type")]
    pub type_: Luks2DigestType,
    pub keyslots: Vec<String>,
    pub segments: Vec<String>,
    #[serde(with = "Base64Standard")]
    pub salt: Vec<u8>,
    #[serde(with = "Base64Standard")]
    pub digest: Vec<u8>,
    // only pbkdf2 is supported currently
    pub hash: String,
    pub iterations: u64,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Luks2KeyslotType {
    Luks2,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Luks2KeyslotAfType {
    Luks1,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2KeyslotAf {
    #[serde(rename = "type")]
    pub type_: Luks2KeyslotAfType,
    pub stripes: u32,
    pub hash: String,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Luks2KeyslotAreaType {
    Raw,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2KeyslotArea {
    #[serde(rename = "type")]
    pub type_: Luks2KeyslotAreaType,
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub offset: u64,
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub size: u64,
    pub encryption: String,
    pub key_size: u16,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Luks2KeyslotKdf {
    Pbkdf2 {
        #[serde(with = "Base64Standard")]
        salt: Vec<u8>,
        hash: String,
        iterations: u32,
    },
    Argon2i {
        #[serde(with = "Base64Standard")]
        salt: Vec<u8>,
        time: u32,
        memory: u32,
        cpus: u32,
    },
    Argon2id {
        #[serde(with = "Base64Standard")]
        salt: Vec<u8>,
        time: u32,
        memory: u32,
        cpus: u32,
    },
}

#[derive(Serialize_repr, Deserialize_repr, Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum Luks2KeyslotPriority {
    Ignore = 0,
    Normal = 1,
    High = 2,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2Keyslot {
    #[serde(rename = "type")]
    pub type_: Luks2KeyslotType,
    pub key_size: u32,
    pub area: Luks2KeyslotArea,
    pub kdf: Luks2KeyslotKdf,
    pub af: Luks2KeyslotAf,
    pub priority: Option<Luks2KeyslotPriority>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Luks2SegmentType {
    Crypt,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2SegmentIntegrity {
    #[serde(rename = "type")]
    pub type_: String,
    pub journal_encryption: String,
    pub journal_integrity: String,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2Segment {
    #[serde(rename = "type")]
    pub type_: Luks2SegmentType,
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub offset: u64,
    pub size: String, // TODO: custom serialization
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub iv_tweak: u64,
    pub encryption: String,
    pub sector_size: u32,
    pub integrity: Option<Luks2SegmentIntegrity>,
    pub flags: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2Token {
    #[serde(rename = "type")]
    pub type_: String,
    pub keyslots: Vec<String>,
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Luks2Metadata {
    pub config: Luks2Config,
    pub digests: HashMap<u16, Luks2Digest>,
    pub keyslots: HashMap<u16, Luks2Keyslot>,
    pub segments: HashMap<u16, Luks2Segment>,
    pub tokens: HashMap<u16, Luks2Token>,
}

impl TryFrom<&str> for Luks2Metadata {
    type Error = Box<dyn error::Error>;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let res = serde_json::from_str(value)?;
        Ok(res)
    }
}

impl TryFrom<&Luks2Metadata> for String {
    type Error = Box<dyn error::Error>;

    fn try_from(m: &Luks2Metadata) -> Result<Self, Self::Error> {
        let res = serde_json::to_string(m)?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_config_flag_from() {
        assert_eq!(
            serde_json::from_str::<Luks2ConfigFlag>(r#""allow-discards""#).unwrap(),
            Luks2ConfigFlag::AllowDiscards
        );
        assert_eq!(
            serde_json::from_str::<Luks2ConfigFlag>(r#""same-cpu-crypt""#).unwrap(),
            Luks2ConfigFlag::SameCpuCrypt
        );
        assert_eq!(
            serde_json::from_str::<Luks2ConfigFlag>(r#""submit-from-crypt-cpus""#).unwrap(),
            Luks2ConfigFlag::SubmitFromCryptCpus
        );
        assert_eq!(
            serde_json::from_str::<Luks2ConfigFlag>(r#""no-journal""#).unwrap(),
            Luks2ConfigFlag::NoJournal
        );
        assert_eq!(
            serde_json::from_str::<Luks2ConfigFlag>(r#""random-flag""#).unwrap(),
            Luks2ConfigFlag::Unknown
        );
    }

    #[test]
    fn test_json_config_flag_to() {
        assert_eq!(
            r#""allow-discards""#,
            serde_json::to_string(&Luks2ConfigFlag::AllowDiscards).unwrap()
        );
        assert_eq!(
            r#""same-cpu-crypt""#,
            serde_json::to_string(&Luks2ConfigFlag::SameCpuCrypt).unwrap()
        );
        assert_eq!(
            r#""submit-from-crypt-cpus""#,
            serde_json::to_string(&Luks2ConfigFlag::SubmitFromCryptCpus).unwrap()
        );
        assert_eq!(
            r#""no-journal""#,
            serde_json::to_string(&Luks2ConfigFlag::NoJournal).unwrap()
        );
        assert_eq!(true, serde_json::to_string(&Luks2ConfigFlag::Unknown).is_err());
    }

    #[test]
    fn test_json_config() {
        let js = r#"{"json_size":"12288","keyslots_size":"16744448"}"#;
        let c: Luks2Config = serde_json::from_str(js).unwrap();
        assert_eq!(c.json_size, 12288);
        assert_eq!(c.keyslots_size, 16744448);
        assert_eq!(c.flags, None);
        assert_eq!(c.requirements, None);

        let to_js = serde_json::to_string(&c).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_digests() {
        let js = r#"{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"salt":"WYkbZOppCHRvwDvrVIbxKimZ4qjXDSizlcMRvyE7EM0=","digest":"SH2Ks6EOcW9r8Q82mLQG8+5H3TvAYLdLw8VuP7Vo5eM=","hash":"sha256","iterations":223672}"#;
        let d: Luks2Digest = serde_json::from_str(js).unwrap();

        assert_eq!(d.type_, Luks2DigestType::Pbkdf2);
        assert_eq!(d.keyslots, vec!("0"));
        assert_eq!(d.segments, vec!("0"));
        assert_eq!(d.hash, "sha256");
        assert_eq!(d.iterations, 223672);
        assert_eq!(
            d.salt,
            [
                89u8, 137, 27, 100, 234, 105, 8, 116, 111, 192, 59, 235, 84, 134, 241, 42, 41, 153, 226, 168, 215, 13,
                40, 179, 149, 195, 17, 191, 33, 59, 16, 205
            ]
        );
        assert_eq!(
            d.digest,
            [
                72u8, 125, 138, 179, 161, 14, 113, 111, 107, 241, 15, 54, 152, 180, 6, 243, 238, 71, 221, 59, 192, 96,
                183, 75, 195, 197, 110, 63, 181, 104, 229, 227
            ]
        );

        let to_js = serde_json::to_string(&d).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_keyslot_af() {
        let js = r#"{"type":"luks1","stripes":4000,"hash":"sha256"}"#;
        let a: Luks2KeyslotAf = serde_json::from_str(js).unwrap();

        assert_eq!(a.type_, Luks2KeyslotAfType::Luks1);
        assert_eq!(a.stripes, 4000);
        assert_eq!(a.hash, "sha256");

        let to_js = serde_json::to_string(&a).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_keyslot_area() {
        let js = r#"{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64}"#;
        let a: Luks2KeyslotArea = serde_json::from_str(js).unwrap();

        assert_eq!(a.type_, Luks2KeyslotAreaType::Raw);
        assert_eq!(a.offset, 32768);
        assert_eq!(a.size, 258048);
        assert_eq!(a.encryption, "aes-xts-plain64");
        assert_eq!(a.key_size, 64);

        let to_js = serde_json::to_string(&a).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_keyslot_kdf_pbkdf2() {
        let js = r#"{"type":"pbkdf2","salt":"SH2Ks6EOcW9r8Q82mLQG8+5H3TvAYLdLw8VuP7Vo5eM=","hash":"sha256","iterations":1234}"#;
        let k: Luks2KeyslotKdf = serde_json::from_str(js).unwrap();

        match &k {
            Luks2KeyslotKdf::Pbkdf2 { salt, hash, iterations } => {
                assert_eq!(
                    salt[..],
                    [
                        72u8, 125, 138, 179, 161, 14, 113, 111, 107, 241, 15, 54, 152, 180, 6, 243, 238, 71, 221, 59,
                        192, 96, 183, 75, 195, 197, 110, 63, 181, 104, 229, 227
                    ]
                );
                assert_eq!(hash, "sha256");
                assert_eq!(*iterations, 1234);
            }
            _ => assert!(false, "expected pbkdf2"),
        }

        let to_js = serde_json::to_string(&k).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_keyslot_kdf_argon2i() {
        let js = r#"{"type":"argon2i","salt":"cNqP5YVtK2DRlLvTPZU8LXy4jWi1+QJPH+Gz3WouBTI=","time":8,"memory":1048576,"cpus":4}"#;
        let k: Luks2KeyslotKdf = serde_json::from_str(js).unwrap();

        match &k {
            Luks2KeyslotKdf::Argon2i {
                salt,
                time,
                memory,
                cpus,
            } => {
                assert_eq!(
                    salt[..],
                    [
                        112u8, 218, 143, 229, 133, 109, 43, 96, 209, 148, 187, 211, 61, 149, 60, 45, 124, 184, 141,
                        104, 181, 249, 2, 79, 31, 225, 179, 221, 106, 46, 5, 50
                    ]
                );
                assert_eq!(*time, 8);
                assert_eq!(*memory, 1048576);
                assert_eq!(*cpus, 4);
            }
            _ => assert!(false, "expected argon2i"),
        }

        let to_js = serde_json::to_string(&k).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_keyslot_kdf_argon2id() {
        let js = r#"{"type":"argon2id","salt":"cNqP5YVtK2DRlLvTPZU8LXy4jWi1+QJPH+Gz3WouBTI=","time":8,"memory":1048576,"cpus":4}"#;
        let k: Luks2KeyslotKdf = serde_json::from_str(js).unwrap();

        match &k {
            Luks2KeyslotKdf::Argon2id {
                salt,
                time,
                memory,
                cpus,
            } => {
                assert_eq!(
                    salt[..],
                    [
                        112u8, 218, 143, 229, 133, 109, 43, 96, 209, 148, 187, 211, 61, 149, 60, 45, 124, 184, 141,
                        104, 181, 249, 2, 79, 31, 225, 179, 221, 106, 46, 5, 50
                    ]
                );
                assert_eq!(*time, 8);
                assert_eq!(*memory, 1048576);
                assert_eq!(*cpus, 4);
            }
            _ => assert!(false, "expected argon2id"),
        }

        let to_js = serde_json::to_string(&k).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_segment() {
        let js = r#"{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}"#;
        let s: Luks2Segment = serde_json::from_str(js).unwrap();

        assert_eq!(s.type_, Luks2SegmentType::Crypt);
        assert_eq!(s.offset, 16777216);
        assert_eq!(s.size, "dynamic");
        assert_eq!(s.iv_tweak, 0);
        assert_eq!(s.encryption, "aes-xts-plain64");
        assert_eq!(s.sector_size, 512);

        let to_js = serde_json::to_string(&s).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_token() {
        let js = r#"{"type":"luks2-keyring","keyslots":["0","1"],"key_description":"my:key"}"#;
        let t: Luks2Token = serde_json::from_str(js).unwrap();

        let mut m = serde_json::Map::new();
        let _ = m.insert(
            "key_description".to_owned(),
            serde_json::Value::String("my:key".to_owned()),
        );

        assert_eq!(t.type_, "luks2-keyring");
        assert_eq!(t.keyslots, ["0", "1"]);
        assert_eq!(t.other, m);

        let to_js = serde_json::to_string(&t).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_metadata_simple() {
        let js = r#"{"config":{"json_size":"12288","keyslots_size":"16744448"},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"salt":"WYkbZOppCHRvwDvrVIbxKimZ4qjXDSizlcMRvyE7EM0=","digest":"SH2Ks6EOcW9r8Q82mLQG8+5H3TvAYLdLw8VuP7Vo5eM=","hash":"sha256","iterations":223672}},"keyslots":{"0":{"type":"luks2","key_size":64,"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2i","salt":"cNqP5YVtK2DRlLvTPZU8LXy4jWi1+QJPH+Gz3WouBTI=","time":8,"memory":1048576,"cpus":4},"af":{"type":"luks1","stripes":4000,"hash":"sha256"}}},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}},"tokens":{}}"#;
        let m: Luks2Metadata = serde_json::from_str(js).unwrap();

        let expected = Luks2Metadata {
            config: Luks2Config {
                json_size: 12288,
                keyslots_size: 16744448,
                flags: None,
                requirements: None,
            },
            digests: [(
                0u16,
                Luks2Digest {
                    type_: Luks2DigestType::Pbkdf2,
                    keyslots: vec!["0".to_owned()],
                    segments: vec!["0".to_owned()],
                    salt: vec![
                        89, 137, 27, 100, 234, 105, 8, 116, 111, 192, 59, 235, 84, 134, 241, 42, 41, 153, 226, 168,
                        215, 13, 40, 179, 149, 195, 17, 191, 33, 59, 16, 205,
                    ],
                    digest: vec![
                        72, 125, 138, 179, 161, 14, 113, 111, 107, 241, 15, 54, 152, 180, 6, 243, 238, 71, 221, 59,
                        192, 96, 183, 75, 195, 197, 110, 63, 181, 104, 229, 227,
                    ],
                    hash: "sha256".to_string(),
                    iterations: 223672,
                },
            )]
            .iter()
            .cloned()
            .collect(),
            keyslots: [(
                0u16,
                Luks2Keyslot {
                    type_: Luks2KeyslotType::Luks2,
                    key_size: 64,
                    area: Luks2KeyslotArea {
                        type_: Luks2KeyslotAreaType::Raw,
                        offset: 32768,
                        size: 258048,
                        encryption: "aes-xts-plain64".to_string(),
                        key_size: 64,
                    },
                    kdf: Luks2KeyslotKdf::Argon2i {
                        salt: vec![
                            112, 218, 143, 229, 133, 109, 43, 96, 209, 148, 187, 211, 61, 149, 60, 45, 124, 184, 141,
                            104, 181, 249, 2, 79, 31, 225, 179, 221, 106, 46, 5, 50,
                        ],
                        time: 8,
                        memory: 1048576,
                        cpus: 4,
                    },
                    af: Luks2KeyslotAf {
                        type_: Luks2KeyslotAfType::Luks1,
                        stripes: 4000,
                        hash: "sha256".to_string(),
                    },
                    priority: None,
                },
            )]
            .iter()
            .cloned()
            .collect(),
            segments: [(
                0u16,
                Luks2Segment {
                    type_: Luks2SegmentType::Crypt,
                    offset: 16777216,
                    size: "dynamic".to_string(),
                    iv_tweak: 0,
                    encryption: "aes-xts-plain64".to_string(),
                    sector_size: 512,
                    integrity: None,
                    flags: None,
                },
            )]
            .iter()
            .cloned()
            .collect(),
            tokens: HashMap::new(),
        };

        assert_eq!(m, expected);

        let to_js = serde_json::to_string(&m).unwrap();
        assert_eq!(to_js, js);
    }

    #[test]
    fn test_json_metadata_example() {
        let js = r#"{
          "keyslots":{
            "0":{
              "type":"luks2",
              "key_size":32,
              "af":{
                "type":"luks1",
                "stripes":4000,
                "hash":"sha256"
              },
              "area":{
                "type":"raw",
                "encryption":"aes-xts-plain64",
                "key_size":32,
                "offset":"32768",
                "size":"131072"
              },
              "kdf":{
                "type":"argon2i",
                "time":4,
                "memory":235980,
                "cpus":2,
                "salt":"z6vz4xK7cjan92rDA5JF8O6Jk2HouV0O8DMB6GlztVk="
              }
            },
            "1":{
              "type":"luks2",
              "key_size":32,
              "af":{
                "type":"luks1",
                "stripes":4000,
                "hash":"sha256"
              },
              "area":{
                "type":"raw",
                "encryption":"aes-xts-plain64",
                "key_size":32,
                "offset":"163840",
                "size":"131072"
              },
              "kdf":{
                "type":"pbkdf2",
                "hash":"sha256",
                "iterations":1774240,
                "salt":"vWcwY3rx2fKpXW2Q6oSCNf8j5bvdJyEzB6BNXECGDsI="
              }
            }
          },
          "tokens":{
            "0":{
              "type":"luks2-keyring",
              "keyslots":[
                "1"
              ],
              "key_description":"MyKeyringKeyID"
            }
          },
          "segments":{
            "0":{
              "type":"crypt",
              "offset":"4194304",
              "iv_tweak":"0",
              "size":"dynamic",
              "encryption":"aes-xts-plain64",
              "sector_size":512
            }
          },
          "digests":{
            "0":{
              "type":"pbkdf2",
              "keyslots":[
                "0",
                "1"
              ],
              "segments":[
                "0"
              ],
              "hash":"sha256",
              "iterations":110890,
              "salt":"G8gqtKhS96IbogHyJLO+t9kmjLkx+DM3HHJqQtgc2Dk=",
              "digest":"C9JWko5m+oYmjg6R0t/98cGGzLr/4UaG3hImSJMivfc="
            }
          },
          "config":{
            "json_size":"12288",
            "keyslots_size":"4161536",
            "flags":[
              "allow-discards"
            ]
          }
        }
        "#;
        let m: Luks2Metadata = serde_json::from_str(js).unwrap();

        // just check that it parses
        assert_eq!(m.config.flags, Some(vec!(Luks2ConfigFlag::AllowDiscards)));
    }
}
