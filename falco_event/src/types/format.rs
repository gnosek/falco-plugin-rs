use std::fmt::Formatter;

pub trait Format<F> {
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result;
}

impl<T, F> Format<F> for Option<T>
where
    T: Format<F>,
{
    fn format(&self, fmt: &mut Formatter) -> std::fmt::Result {
        match self {
            Some(inner) => inner.format(fmt),
            None => fmt.write_str("NULL"),
        }
    }
}

#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub mod format_type {
    pub struct PF_NA;
    pub struct PF_DEC;
    pub struct PF_HEX;
    pub struct PF_10_PADDED_DEC;
    pub struct PF_ID;
    pub struct PF_DIR;
    pub struct PF_OCT;
}
