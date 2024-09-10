#[doc(hidden)]
#[macro_export]
macro_rules! impl_export_table_static_fields {
    (for $name:ident has_dynamic = $has_dynamic:literal {
        $($field_name:literal: $field_type:ty; readonly = $readonly:literal,)*
    }) => {
        const STATIC_FIELDS: &'static [(&'static ::std::ffi::CStr, $crate::internals::tables::export::FieldTypeId, bool)] = &[
            $(($field_name, <$field_type as $crate::internals::tables::export::StaticField>::TYPE_ID, $readonly),)*
        ];

        const HAS_DYNAMIC_FIELDS: bool = $has_dynamic;
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_export_table_get {
    (
        $self:ident,
        static: $($i:literal: $field_name:ident,)*
        dynamic:,
    ) => {
        fn get(
            &$self,
            key: usize,
            type_id: $crate::internals::tables::export::FieldTypeId,
            out: &mut $crate::api::ss_plugin_state_data,
        ) -> Result<(), $crate::anyhow::Error> {
            use $crate::internals::tables::export::FieldValue;
            match key {
                $($i => $self.$field_name.to_data(out, type_id),)*
                _ => Err($crate::anyhow::anyhow!("Table does not have dynamic fields")
                        .context($crate::FailureReason::NotSupported)),
            }
        }
    };
    (
        $self:ident,
        static: $($i:literal: $field_name:ident,)*
        dynamic: $dynamic_field:ident,
    ) => {
        fn get(
            &$self,
            key: usize,
            type_id: $crate::internals::tables::export::FieldTypeId,
            out: &mut $crate::api::ss_plugin_state_data,
        ) -> Result<(), $crate::anyhow::Error> {
            use $crate::internals::tables::export::FieldValue;
            match key {
                $($i => $self.$field_name.to_data(out, type_id),)*
                _ => $crate::internals::tables::export::Entry::get(&$self.$dynamic_field, key, type_id, out),
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_export_table_set {
    (
        $self:ident,
        static: $($i:literal: $field_name:ident,)*
        dynamic:,
    ) => {
        fn set(&mut $self, key: usize, value: $crate::internals::tables::export::DynamicFieldValue)
            -> std::result::Result<(), $crate::anyhow::Error> {
            match key {
                $($i => Ok($self.$field_name = value.try_into()?),)*
                _ => Err($crate::anyhow::anyhow!("Table does not have dynamic fields")
                        .context($crate::FailureReason::NotSupported)),
            }
        }
    };
    (
        $self:ident,
        static: $($i:literal: $field_name:ident,)*
        dynamic: $dynamic_field:ident,
    ) => {
        fn set(&mut $self, key: usize, value: $crate::internals::tables::export::DynamicFieldValue)
            -> std::result::Result<(), $crate::anyhow::Error> {
            match key {
                $($i => Ok($self.$field_name = value.try_into()?),)*
                _ => $self.$dynamic_field.set(key, value),
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_export_table {
    (for $name:ident; dynamic = $dynamic_field:ident {
        $([$i:literal] $field_name_str:literal as $field_name:ident: $field_type:ty; readonly = $readonly:literal)*
    }) => {
        impl $crate::internals::tables::export::Entry for $name {
            const STATIC_FIELDS: &'static [(&'static ::std::ffi::CStr, $crate::internals::tables::FieldTypeId, bool)] = &[
                $(($field_name_str, <$field_type as $crate::internals::tables::export::StaticField>::TYPE_ID, $readonly),)*
            ];

            const HAS_DYNAMIC_FIELDS: bool = true;

            $crate::impl_export_table_get!(
                self,
                static: $($i: $field_name,)*
                dynamic: $dynamic_field,
            );
            $crate::impl_export_table_set!(
                self,
                static: $($i: $field_name,)*
                dynamic: $dynamic_field,
            );
        }
    };

    (for $name:ident; dynamic = {
        $([$i:literal] $field_name_str:literal as $field_name:ident: $field_type:ty; readonly = $readonly:literal)*
    }) => {
        impl $crate::internals::tables::export::Entry for $name {
            const STATIC_FIELDS: &'static [(&'static ::std::ffi::CStr, $crate::internals::tables::FieldTypeId, bool)] = &[
                $(($field_name_str, <$field_type as $crate::internals::tables::export::StaticField>::TYPE_ID, $readonly),)*
            ];

            const HAS_DYNAMIC_FIELDS: bool = false;

            $crate::impl_export_table_get!(
                self,
                static: $($i: $field_name,)*
                dynamic:,
            );
            $crate::impl_export_table_set!(
                self,
                static: $($i: $field_name,)*
                dynamic:,
            );
        }
    };
}
