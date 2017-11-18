use std;

/// `BoxedError` is a general-purpose error type.
pub type BoxedError = Box<std::error::Error + Send + Sync>;

macro_rules! declare_static_error_type {
    (impl $typename:ident, $description:expr) => {
        impl std::fmt::Display for $typename {
            fn fmt(&self, f: &mut std::fmt::Formatter) ->
                Result<(), std::fmt::Error>
            {
                f.write_str(std::error::Error::description(self))
            }
        }

        impl std::error::Error for $typename {
            fn description(&self) -> &str {
                $description
            }
        }
    };

    (pub $typename:ident, $description:expr) => {
        #[derive(Debug, Eq, PartialEq)]
        pub struct $typename;
        declare_static_error_type!(impl $typename, $description);
    };

    ($typename:ident, $description:expr) => {
        #[derive(Debug, Eq, PartialEq)]
        struct $typename;
        declare_static_error_type!(impl $typename, $description);
    };
}

declare_static_error_type!(pub EEndOfInput, "Got end of input");
