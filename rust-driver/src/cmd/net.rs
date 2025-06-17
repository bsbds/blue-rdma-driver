use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

const BLUE_RDMA_SYSFS_PATH: &str = "/sys/class/infiniband/bluerdma0";

pub(crate) struct NetMetaReader;

impl NetMetaReader {
    pub(crate) fn read_mac() -> io::Result<u64> {
        let mac = Self::read_attribute("mac")?;
        let bytes = mac
            .split(':')
            .map(|s| u8::from_str_radix(s, 16))
            .collect::<Result<Vec<_>, _>>()
            .expect("invalid mac format");
        assert_eq!(bytes.len(), 6, "invalid mac format");

        let mut result = 0;
        for b in bytes {
            result = (result << 8) | u64::from(b);
        }

        Ok(result)
    }

    #[allow(clippy::indexing_slicing)]
    pub(crate) fn read_ip() -> io::Result<Option<u32>> {
        let gids = Self::read_attribute("gids")?;
        for gid in gids.lines() {
            let bytes = gid
                .split(':')
                .map(|s| u16::from_str_radix(s, 16))
                .collect::<Result<Vec<_>, _>>()
                .expect("invalid gid format");
            assert_eq!(bytes.len(), 8, "invalid gid format");
            // only consider the first ipv4 address
            if bytes[0] == 0
                && bytes[1] == 0
                && bytes[2] == 0
                && bytes[3] == 0
                && bytes[4] == 0
                && bytes[5] == 0xffff
            {
                let result = (u32::from(bytes[6]) << 16) & u32::from(bytes[7]);
                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    fn read_attribute(attr: &str) -> io::Result<String> {
        let path = PathBuf::from(BLUE_RDMA_SYSFS_PATH).join(attr);
        let mut content = String::new();
        let _ignore = File::open(&path)?.read_to_string(&mut content)?;
        Ok(content.trim().to_owned())
    }
}
