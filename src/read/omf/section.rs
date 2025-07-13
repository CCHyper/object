#[derive(Debug)]
pub struct OmfSection<'data> {
    pub name: &'data str,
    pub segment_index: u8,
    pub is_code: bool,
    pub is_32bit: bool,
    pub data: &'data [u8],
}

impl<'data> OmfSection<'data> {
    pub fn parse(mut data: &'data [u8], lnames: &[&'data str]) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("SEGDEF too short");
        }
        let attr = data[0];
        data = &data[1..];

        let is_code = attr & 0x1 == 0;
        let is_32bit = attr & 0x4 != 0;

        let seg_len = if is_32bit {
            if data.len() < 4 { return Err("Missing 32-bit seg length"); }
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize
        } else {
            if data.len() < 2 { return Err("Missing 16-bit seg length"); }
            u16::from_le_bytes([data[0], data[1]]) as usize
        };

        let name_idx = *data.last().unwrap_or(&0) as usize;
        let name = lnames.get(name_idx - 1).copied().unwrap_or("");

        Ok(Self {
            name,
            segment_index: name_idx as u8,
            is_code,
            is_32bit,
            data: &[],
        })
    }
}
