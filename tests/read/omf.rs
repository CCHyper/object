#[cfg(test)]
mod tests {
    use object::{Object, ObjectSection};

    #[test]
    fn test_parse_simple_omf() {
        let raw = include_bytes!("../../testfiles/omf/simple.obj");
        let obj = object::read::File::parse(raw.as_ref()).expect("parse");

        let symbols = obj.symbols().collect::<Vec<_>>();
        assert!(!symbols.is_empty(), "Should parse at least one symbol");

        let sections = obj.sections().collect::<Vec<_>>();
        assert!(!sections.is_empty(), "Should parse at least one section");

        for sec in &sections {
            println!("Section: {} size={}", sec.name().unwrap_or("?"), sec.size());
        }
    }
}
