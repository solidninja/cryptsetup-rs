#![deny(warnings)]
#[warn(unused_must_use)]
// The following code has been ported from libcryptsetup
extern crate byteorder;
extern crate either;
extern crate uuid;

use either::Either::{Left, Right};
use std::convert;
use std::error;
use std::fmt::{Display, Error as FmtError, Formatter};
use std::io;
use std::io::Read;
use std::str;
use uuid::Uuid;

// TODO: missing docs

#[derive(Debug)]
pub enum Error {
    InvalidMagic,
    InvalidStringEncoding(str::Utf8Error),
    InvalidVersion,
    InvalidUuid(uuid::Error),
    ReadError(io::Error),
    ReadIncorrectHeaderSize,
    HeaderProcessingError,
    EmptyString,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{:?}", &self)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            &Error::InvalidStringEncoding(e) => Some(e),
            &Error::InvalidUuid(e) => Some(e),
            &Error::ReadError(e) => Some(e),
            _ => None,
        }
    }
}

pub enum LuksHeader {
    Luks1(LuksHeaderV1),
    Luks2(LuksHeaderV2),
}

impl LuksHeader {
    pub fn read<R: Read>(mut reader: R) -> Result<LuksHeader, Error> {
        let res = match raw::read_luks_header(&mut reader)? {
            Left(raw) => LuksHeader::Luks1(LuksHeaderV1 { raw }),
            Right(raw) => LuksHeader::Luks2(LuksHeaderV2 { raw }),
        };
        Ok(res)
    }
}

pub struct LuksHeaderV1 {
    raw: raw::luks_phdr,
}

pub struct LuksHeaderV2 {
    raw: raw::luks2_phdr,
}

pub trait LuksVersionedHeader {
    fn version(&self) -> u16;
    fn uuid(&self) -> Result<uuid::Uuid, Error>;
}

impl LuksVersionedHeader for LuksHeader {
    fn version(&self) -> u16 {
        match &self {
            &LuksHeader::Luks1(h) => h.version(),
            &LuksHeader::Luks2(h) => h.version(),
        }
    }

    fn uuid(&self) -> Result<Uuid, Error> {
        match &self {
            &LuksHeader::Luks1(h) => h.uuid(),
            &LuksHeader::Luks2(h) => h.uuid(),
        }
    }
}

pub trait Luks1Header: LuksVersionedHeader {
    fn cipher_name(&self) -> Result<&str, Error>;
    fn cipher_mode(&self) -> Result<&str, Error>;
    fn hash_spec(&self) -> Result<&str, Error>;
    fn payload_offset(&self) -> u32;
    fn key_bytes(&self) -> u32;
    fn mk_digest(&self) -> &[u8];
    fn mk_digest_salt(&self) -> &[u8];
    fn mk_digest_iterations(&self) -> u32;
}

impl LuksVersionedHeader for LuksHeaderV1 {
    fn version(&self) -> u16 {
        self.raw.version
    }

    fn uuid(&self) -> Result<Uuid, Error> {
        raw::uuid_buf_to_uuid(&self.raw.uuid)
    }
}

impl LuksVersionedHeader for LuksHeaderV2 {
    fn version(&self) -> u16 {
        self.raw.version
    }

    fn uuid(&self) -> Result<Uuid, Error> {
        raw::uuid_buf_to_uuid(&self.raw.uuid)
    }
}

impl Luks1Header for LuksHeaderV1 {
    fn cipher_name(&self) -> Result<&str, Error> {
        raw::u8_buf_to_str(&self.raw.cipherName)?.ok_or(Error::EmptyString)
    }

    fn cipher_mode(&self) -> Result<&str, Error> {
        raw::u8_buf_to_str(&self.raw.cipherMode)?.ok_or(Error::EmptyString)
    }

    fn hash_spec(&self) -> Result<&str, Error> {
        raw::u8_buf_to_str(&self.raw.hashSpec)?.ok_or(Error::EmptyString)
    }

    fn payload_offset(&self) -> u32 {
        self.raw.payloadOffset
    }

    fn key_bytes(&self) -> u32 {
        self.raw.keyBytes
    }

    fn mk_digest(&self) -> &[u8] {
        &self.raw.mkDigest
    }

    fn mk_digest_salt(&self) -> &[u8] {
        &self.raw.mkDigestSalt
    }

    fn mk_digest_iterations(&self) -> u32 {
        self.raw.mkDigestIterations
    }
}

pub trait Luks2Header: LuksVersionedHeader {
    fn label(&self) -> Result<Option<&str>, Error>;
    fn subsystem(&self) -> Result<Option<&str>, Error>;
    fn seqid(&self) -> u64;
    fn header_size(&self) -> u64;
    fn header_offset(&self) -> u64;

    // TODO add luks2 specifics (however the json header structure is not neccessary at the moment so not read)
}

impl Luks2Header for LuksHeaderV2 {
    fn label(&self) -> Result<Option<&str>, Error> {
        let label_opt = raw::u8_buf_to_str(&self.raw.label)?;
        Ok(label_opt)
    }

    fn subsystem(&self) -> Result<Option<&str>, Error> {
        let subsystem_opt = raw::u8_buf_to_str(&self.raw.subsystem)?;
        Ok(subsystem_opt)
    }

    fn seqid(&self) -> u64 {
        self.raw.seqid
    }

    fn header_size(&self) -> u64 {
        self.raw.hdr_size
    }

    fn header_offset(&self) -> u64 {
        self.raw.hdr_offset
    }
}

impl convert::From<str::Utf8Error> for Error {
    fn from(error: str::Utf8Error) -> Error {
        Error::InvalidStringEncoding(error)
    }
}

impl convert::From<uuid::Error> for Error {
    fn from(error: uuid::Error) -> Error {
        Error::InvalidUuid(error)
    }
}

impl convert::From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::ReadError(error)
    }
}

mod raw {
    #![allow(non_snake_case)]

    use std::convert::From;
    use std::io::{Cursor, Read};
    use std::mem;
    use std::str;

    use byteorder::{BigEndian, ReadBytesExt};
    use either::Either;
    use either::Either::{Left, Right};
    use uuid;

    const V1: u16 = 1;
    const V2: u16 = 2;

    const LUKS_MAGIC_L: usize = 6;
    const LUKS_CIPHERNAME_L: usize = 32;
    const LUKS_CIPHERMODE_L: usize = 32;
    const LUKS_HASHSPEC_L: usize = 32;
    const LUKS_DIGESTSIZE: usize = 20;
    const LUKS_SALTSIZE: usize = 32;
    const UUID_STRING_L: usize = 40;
    const LUKS2_LABEL_L: usize = 48;
    const LUKS2_SALT_L: usize = 64;
    const LUKS2_CHECKSUM_ALG_L: usize = 32;
    const LUKS2_CHECKSUM_L: usize = 64;

    const LUKS_MAGIC: &'static [u8; LUKS_MAGIC_L] = b"LUKS\xba\xbe";

    // used for secondary header, currently unsupported here TODO
    const _LUKS2_MAGIC_2: &'static [u8; LUKS_MAGIC_L] = b"SKUL\xba\xbe";

    const LUKS2_PHDR_PADDING_L: usize = 184;

    // note: these are not packed because it's unsafe to take a slice
    #[repr(C)]
    pub struct luks_phdr {
        pub magic: [u8; LUKS_MAGIC_L],
        pub version: u16,
        pub cipherName: [u8; LUKS_CIPHERNAME_L],
        pub cipherMode: [u8; LUKS_CIPHERMODE_L],
        pub hashSpec: [u8; LUKS_HASHSPEC_L],
        pub payloadOffset: u32,
        pub keyBytes: u32,
        pub mkDigest: [u8; LUKS_DIGESTSIZE],
        pub mkDigestSalt: [u8; LUKS_SALTSIZE],
        pub mkDigestIterations: u32,
        pub uuid: [u8; UUID_STRING_L],
    }

    #[repr(C)]
    pub struct luks2_phdr {
        pub magic: [u8; LUKS_MAGIC_L],
        pub version: u16,
        pub hdr_size: u64,
        pub seqid: u64,
        pub label: [u8; LUKS2_LABEL_L],
        pub checksum_alg: [u8; LUKS2_CHECKSUM_ALG_L],
        pub salt: [u8; LUKS2_SALT_L],
        pub uuid: [u8; UUID_STRING_L],
        pub subsystem: [u8; LUKS2_LABEL_L],
        pub hdr_offset: u64,
        pub _padding: [u8; LUKS2_PHDR_PADDING_L],
        pub csum: [u8; LUKS2_CHECKSUM_L],
    }

    pub fn read_luks_header<R: Read>(reader: &mut R) -> Result<Either<luks_phdr, luks2_phdr>, super::Error> {
        let mut start_buf = [0u8; 8];
        reader.read_exact(&mut start_buf)?;

        let mut cursor = Cursor::new(start_buf);

        let mut magic_buf = [0u8; LUKS_MAGIC_L];
        let _magic_len = cursor.read(&mut magic_buf)?;

        let version = cursor.read_u16::<BigEndian>()?;

        if magic_buf == &LUKS_MAGIC[..] && version == V1 {
            let mut buf = [0u8; mem::size_of::<luks_phdr>()];
            buf[..8].copy_from_slice(&start_buf);
            reader.read_exact(&mut buf[8..])?;
            luks_phdr::from_buf(&mut buf).map(|h| Left(h))
        } else if magic_buf == &LUKS_MAGIC[..] && version == V2 {
            let mut buf = [0u8; mem::size_of::<luks2_phdr>()];
            buf[..8].copy_from_slice(&start_buf);
            reader.read_exact(&mut buf[8..])?;
            luks2_phdr::from_buf(&mut buf).map(|h| Right(h))
        } else if magic_buf != &LUKS_MAGIC[..] {
            Err(super::Error::InvalidMagic)
        } else {
            Err(super::Error::InvalidVersion)
        }
    }

    impl luks_phdr {
        pub fn from_buf(buf: &[u8]) -> Result<luks_phdr, super::Error> {
            // FIXME - this is not particularly pretty

            if buf.len() < mem::size_of::<luks_phdr>() {
                return Err(super::Error::ReadIncorrectHeaderSize);
            }
            let mut cursor = Cursor::new(buf);
            let mut magic_buf = [0u8; LUKS_MAGIC_L];
            let magic_len = cursor.read(&mut magic_buf)?;

            if magic_len != LUKS_MAGIC_L || magic_buf != &LUKS_MAGIC[..] {
                return Err(super::Error::InvalidMagic);
            }

            let version = cursor.read_u16::<BigEndian>()?;
            if version != V1 {
                return Err(super::Error::InvalidVersion);
            }

            let mut cipher_name_buf = [0u8; LUKS_CIPHERNAME_L];
            let cipher_name_len = cursor.read(&mut cipher_name_buf)?;
            if cipher_name_len != LUKS_CIPHERNAME_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut cipher_mode_buf = [0u8; LUKS_CIPHERMODE_L];
            let cipher_mode_len = cursor.read(&mut cipher_mode_buf)?;
            if cipher_mode_len != LUKS_CIPHERMODE_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut hash_spec_buf = [0u8; LUKS_HASHSPEC_L];
            let hash_spec_len = cursor.read(&mut hash_spec_buf)?;
            if hash_spec_len != LUKS_HASHSPEC_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let payload_offset = cursor.read_u32::<BigEndian>()?;
            let key_bytes = cursor.read_u32::<BigEndian>()?;

            let mut mk_digest_buf = [0u8; LUKS_DIGESTSIZE];
            let mk_digest_len = cursor.read(&mut mk_digest_buf)?;
            if mk_digest_len != LUKS_DIGESTSIZE {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut mk_digest_salt_buf = [0u8; LUKS_SALTSIZE];
            let mk_digest_salt_len = cursor.read(&mut mk_digest_salt_buf)?;
            if mk_digest_salt_len != LUKS_SALTSIZE {
                return Err(super::Error::HeaderProcessingError);
            }

            let mk_digest_iterations = cursor.read_u32::<BigEndian>()?;

            let mut uuid_buf = [0u8; UUID_STRING_L];
            let uuid_len = cursor.read(&mut uuid_buf)?;
            if uuid_len != UUID_STRING_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let res = luks_phdr {
                magic: magic_buf,
                version: version,
                cipherName: cipher_name_buf,
                cipherMode: cipher_mode_buf,
                hashSpec: hash_spec_buf,
                payloadOffset: payload_offset,
                keyBytes: key_bytes,
                mkDigest: mk_digest_buf,
                mkDigestSalt: mk_digest_salt_buf,
                mkDigestIterations: mk_digest_iterations,
                uuid: uuid_buf,
            };

            Ok(res)
        }
    }

    impl luks2_phdr {
        pub fn from_buf(buf: &[u8]) -> Result<luks2_phdr, super::Error> {
            if buf.len() < mem::size_of::<luks2_phdr>() {
                return Err(super::Error::ReadIncorrectHeaderSize);
            }
            let mut cursor = Cursor::new(buf);
            let mut magic_buf = [0u8; LUKS_MAGIC_L];
            let magic_len = cursor.read(&mut magic_buf)?;

            if magic_len != LUKS_MAGIC_L || magic_buf != &LUKS_MAGIC[..] {
                return Err(super::Error::InvalidMagic);
            }

            let version = cursor.read_u16::<BigEndian>()?;
            if version != V2 {
                return Err(super::Error::InvalidVersion);
            }

            let hdr_size = cursor.read_u64::<BigEndian>()?;
            let seqid = cursor.read_u64::<BigEndian>()?;

            let mut label_buf = [0u8; LUKS2_LABEL_L];
            let label_len = cursor.read(&mut label_buf)?;
            if label_len != LUKS2_LABEL_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut checksum_alg_buf = [0u8; LUKS2_CHECKSUM_ALG_L];
            let checksum_alg_len = cursor.read(&mut checksum_alg_buf)?;
            if checksum_alg_len != LUKS2_CHECKSUM_ALG_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut salt_buf = [0u8; LUKS2_SALT_L];
            let salt_len = cursor.read(&mut salt_buf)?;
            if salt_len != LUKS2_SALT_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut uuid_buf = [0u8; UUID_STRING_L];
            let uuid_len = cursor.read(&mut uuid_buf)?;
            if uuid_len != UUID_STRING_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut subsystem_buf = [0u8; LUKS2_LABEL_L];
            let subsystem_len = cursor.read(&mut subsystem_buf)?;
            if subsystem_len != LUKS2_LABEL_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let hdr_offset = cursor.read_u64::<BigEndian>()?;

            let mut padding_buf = [0u8; LUKS2_PHDR_PADDING_L];
            let padding_len = cursor.read(&mut padding_buf)?;
            if padding_len != LUKS2_PHDR_PADDING_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let mut csum_buf = [0u8; LUKS2_CHECKSUM_L];
            let csum_len = cursor.read(&mut csum_buf)?;
            if csum_len != LUKS2_CHECKSUM_L {
                return Err(super::Error::HeaderProcessingError);
            }

            let res = luks2_phdr {
                magic: magic_buf,
                version,
                hdr_size,
                seqid,
                label: label_buf,
                checksum_alg: checksum_alg_buf,
                salt: salt_buf,
                uuid: uuid_buf,
                subsystem: subsystem_buf,
                hdr_offset,
                _padding: padding_buf,
                csum: csum_buf,
            };

            Ok(res)
        }
    }

    pub fn u8_buf_to_str(buf: &[u8]) -> Result<Option<&str>, super::Error> {
        if let Some(pos) = buf.iter().position(|&c| c == 0) {
            if pos == 0 {
                Ok(None)
            } else {
                str::from_utf8(&buf[0..pos]).map_err(From::from).map(|s| Some(s))
            }
        } else {
            str::from_utf8(buf).map_err(From::from).map(|s| Some(s))
        }
    }

    pub fn uuid_buf_to_uuid(buf: &[u8; UUID_STRING_L]) -> Result<uuid::Uuid, super::Error> {
        let uuid_str = u8_buf_to_str(buf)?.ok_or(super::Error::EmptyString)?;
        uuid::Uuid::parse_str(uuid_str).map_err(From::from)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_luks2_header_from_bytes() {
            let header = b"LUKS\xba\xbe\x00\x02\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00sha256\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00g\x98\x84>\xba \x87\x16\xff\xdc\xdb\xc8\xe1\xd6\xd5\xf6\x01\x94\x9c^E\x84\x1e\xcc\x1c\xc5\xa6\xeb\xaePf\xde\x7f\x95\xfeL\x07\x1f46B\x95Z\xae\xf5\x8f\x88\xc0uj,\x08\xb4NW\r\x8c\xec\xb6D\x15P\x0e\x8f0748f429-3aad-426d-95b4-82005de5ad36\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00>\xc7\x12\xf52$\xac\xd3\xc7G()<\xbb\x8d\x0f\x14\x03\x1e\xe6\x83\xc9\xe8C\x00\xff\xdf\xb8\x8b\x08\x9f4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            let luks2_header = luks2_phdr::from_buf(header).expect("luks2 header");

            assert_eq!(luks2_header.version, 2);
            assert_eq!(luks2_header.hdr_size, 16384);
            assert_eq!(luks2_header.seqid, 3);
            assert_eq!(u8_buf_to_str(&luks2_header.label).unwrap(), None);
            assert_eq!(u8_buf_to_str(&luks2_header.checksum_alg).unwrap(), Some("sha256"));
            assert_eq!(
                luks2_header.salt.to_vec(),
                vec!(
                    103u8, 152, 132, 62, 186, 32, 135, 22, 255, 220, 219, 200, 225, 214, 213, 246, 1, 148, 156, 94, 69,
                    132, 30, 204, 28, 197, 166, 235, 174, 80, 102, 222, 127, 149, 254, 76, 7, 31, 52, 54, 66, 149, 90,
                    174, 245, 143, 136, 192, 117, 106, 44, 8, 180, 78, 87, 13, 140, 236, 182, 68, 21, 80, 14, 143
                )
            );
            assert_eq!(
                u8_buf_to_str(&luks2_header.uuid).unwrap(),
                Some("0748f429-3aad-426d-95b4-82005de5ad36")
            );
            assert_eq!(u8_buf_to_str(&luks2_header.subsystem).unwrap(), None);
            assert_eq!(luks2_header.hdr_offset, 0);
            assert_eq!(
                luks2_header.csum.to_vec(),
                vec!(
                    62u8, 199, 18, 245, 50, 36, 172, 211, 199, 71, 40, 41, 60, 187, 141, 15, 20, 3, 30, 230, 131, 201,
                    232, 67, 0, 255, 223, 184, 139, 8, 159, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                )
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use uuid;

    #[test]
    fn test_luks_header_from_byte_buffer() {
        let header = b"LUKS\xba\xbe\x00\x01aes\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ecb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00sha256\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00 \xcf^\xb4\xc00q\xbe\xd5\xe6\x90\xc8G\xb3\x00\xbe\xba\xd052qp\x92\x0c\x9c\xa9\x07R\\y_D\x08b\xf1\xe6\x8f\x0c\xa95\xad\xdb\x15+\xa5\xd7\xa7\xbf^\x96B\x90z\x00\x00\x03\xe8a1b49d2d-8a7e-4b04-ab2a-89f3408fd198\x00\x00\x00\x00";
        let mut cursor: Cursor<&[u8]> = Cursor::new(header);
        let header = LuksHeader::read(&mut cursor).unwrap();

        if let LuksHeader::Luks1(luks_header) = header {
            assert_eq!(luks_header.version(), 1);
            assert_eq!(luks_header.cipher_name().unwrap(), "aes");
            assert_eq!(luks_header.cipher_mode().unwrap(), "ecb");
            assert_eq!(luks_header.hash_spec().unwrap(), "sha256");
            assert_eq!(luks_header.payload_offset(), 4096);
            assert_eq!(luks_header.key_bytes(), 32);
            assert_eq!(
                luks_header.mk_digest(),
                &[207, 94, 180, 192, 48, 113, 190, 213, 230, 144, 200, 71, 179, 0, 190, 186, 208, 53, 50, 113]
            );
            assert_eq!(
                luks_header.mk_digest_salt(),
                &[
                    112, 146, 12, 156, 169, 7, 82, 92, 121, 95, 68, 8, 98, 241, 230, 143, 12, 169, 53, 173, 219, 21,
                    43, 165, 215, 167, 191, 94, 150, 66, 144, 122
                ]
            );
            assert_eq!(luks_header.mk_digest_iterations(), 1000);
            assert_eq!(
                luks_header.uuid().unwrap(),
                uuid::Uuid::parse_str("a1b49d2d-8a7e-4b04-ab2a-89f3408fd198").unwrap()
            );
        } else {
            assert!(false, "failed to read luks v1 header");
        }
    }

    #[test]
    fn test_luks2_header_from_byte_buffer() {
        let header = b"LUKS\xba\xbe\x00\x02\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00sha256\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00g\x98\x84>\xba \x87\x16\xff\xdc\xdb\xc8\xe1\xd6\xd5\xf6\x01\x94\x9c^E\x84\x1e\xcc\x1c\xc5\xa6\xeb\xaePf\xde\x7f\x95\xfeL\x07\x1f46B\x95Z\xae\xf5\x8f\x88\xc0uj,\x08\xb4NW\r\x8c\xec\xb6D\x15P\x0e\x8f0748f429-3aad-426d-95b4-82005de5ad36\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00>\xc7\x12\xf52$\xac\xd3\xc7G()<\xbb\x8d\x0f\x14\x03\x1e\xe6\x83\xc9\xe8C\x00\xff\xdf\xb8\x8b\x08\x9f4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let mut cursor: Cursor<&[u8]> = Cursor::new(header);
        let header = LuksHeader::read(&mut cursor).unwrap();

        if let LuksHeader::Luks2(luks2_header) = header {
            assert_eq!(luks2_header.version(), 2);
            assert_eq!(
                luks2_header.uuid().unwrap(),
                uuid::Uuid::parse_str("0748f429-3aad-426d-95b4-82005de5ad36").unwrap()
            );
        } else {
            assert!(false, "failed to read luks v2 header");
        }
    }
}
