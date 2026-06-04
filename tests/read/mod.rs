#![cfg(feature = "read")]

mod coff;
mod elf;
mod macho;
#[cfg(feature = "omf")]
mod omf;
