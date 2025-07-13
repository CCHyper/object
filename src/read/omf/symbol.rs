#[derive(Debug)]
pub struct OmfSymbol<'data> {
    pub name: &'data str,
    pub segment_index: u8,
    pub offset: u32,
    pub is_public: bool,
}

impl<'data> OmfSymbol<'data> {
    pub fn parse(mut data: &'data [u8], _lnames: &[&'data str]) -> Result<Vec<Self>, &'static str> {
        let mut symbols = Vec::new();
        while !data.is_empty() {
            let len = data[0] as usize;
            if data.len() < len + 4 {
                return Err("Symbol truncated");
            }
            let name = std::str::from_utf8(&data[1..1+len]).map_err(|_| "Invalid UTF-8")?;
            let offset = u16::from_le_bytes([data[1+len], data[2+len]]) as u32;
            let seg = data[3+len];
            symbols.push(Self {
                name,
                segment_index: seg,
                offset,
                is_public: true,
            });
            data = &data[len + 4..];
        }
        Ok(symbols)
    }
}
