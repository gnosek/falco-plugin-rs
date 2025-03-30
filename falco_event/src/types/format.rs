use std::fmt::{Debug, Display, Formatter, LowerHex, Octal};

// This is only used by the derive macro
#[doc(hidden)]
pub struct OptionFormatter<T>(pub Option<T>);

impl<T: Display> Display for OptionFormatter<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(val) => Display::fmt(val, f),
            None => write!(f, "NULL"),
        }
    }
}

impl<T: Debug> Debug for OptionFormatter<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(val) => Debug::fmt(val, f),
            None => write!(f, "NULL"),
        }
    }
}

impl<T: LowerHex> LowerHex for OptionFormatter<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(val) => LowerHex::fmt(val, f),
            None => write!(f, "NULL"),
        }
    }
}

impl<T: Octal> Octal for OptionFormatter<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(val) => Octal::fmt(val, f),
            None => write!(f, "NULL"),
        }
    }
}
