//! DNSlite is a library for working with the DNS protocol.

#[cfg(test)]
#[macro_use]
extern crate assert_matches;
extern crate byteorder;

#[macro_use]
mod error;

mod ascii;
mod name;
mod serial;
mod testing;

pub mod binary;
pub mod text;

pub use error::BoxedError;
pub use name::{Label, Name, NameBuf, NameLabelIter};
pub use serial::Serial;
