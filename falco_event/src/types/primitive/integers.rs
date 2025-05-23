use crate::fields::{FromBytes, FromBytesError, ToBytes};

macro_rules! impl_int_type {
    ($ty:ty) => {
        impl FromBytes<'_> for $ty {
            #[inline]
            fn from_bytes(buf: &mut &[u8]) -> Result<Self, FromBytesError>
            where
                Self: Sized,
            {
                let value_buf = buf.split_off(..std::mem::size_of::<$ty>()).ok_or_else(|| {
                    FromBytesError::TruncatedField {
                        wanted: std::mem::size_of::<$ty>(),
                        got: buf.len(),
                    }
                })?;
                Ok(<$ty>::from_ne_bytes(value_buf.try_into().unwrap()))
            }
        }

        impl ToBytes for $ty {
            #[inline]
            fn binary_size(&self) -> usize {
                std::mem::size_of::<$ty>()
            }

            #[inline]
            fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
                writer.write_all(self.to_ne_bytes().as_slice())
            }

            #[inline]
            fn default_repr() -> impl ToBytes {
                0 as $ty
            }
        }
    };
}

impl_int_type!(u8);
impl_int_type!(i8);
impl_int_type!(u16);
impl_int_type!(i16);
impl_int_type!(u32);
impl_int_type!(i32);
impl_int_type!(u64);
impl_int_type!(i64);
