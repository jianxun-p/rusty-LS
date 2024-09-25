///
///
/// The `rfc_enum` declares an enum that implements the [`TryFrom`] trait.
///
/// # Example
/// ```rust
/// rfc_enum!{
///     [Eq, PartialEq, Debug]
///     (pub) E: u8;
///     A(0), B(1),
/// };
/// # fn main() {
/// #   debug_assert_eq!(E::try_from(0).unwrap(), E::A);
/// #   debug_assert_eq!(E::try_from(1).unwrap(), E::B);
/// #   for i in 3..=u8::MAX {
/// #       debug_assert_eq!(E::try_from(i).is_err(), true);
/// #   }
/// # }
/// ```
/// This macro will be expanded to:
/// ```rust
/// #[repr(u8)]
/// #[derive(Eq, PartialEq, Debug)]
/// pub enum E {
///     A = 0,
///     B = 1,
/// }
/// impl TryFrom<u8> for E {
///     type Error = TlsError;
///     fn try_from(val: u8) -> Result<Self, Self::Error> {
///         match val {
///             0 => Ok(Self::A),
///             1 => Ok(Self::B),
///             _ => Err( TlsError {
///                     code: TlsErrorCode::ParseError,
///                     msg: format!("Unspecified {} enum value: {}", "E", val),
///                 }),
///         }
///     }
/// }
/// ```
macro_rules! rfc_enum {
    (
        $([$($derive_traits:ident),+])?
        $(($visibility:vis))? $name:ident : $val_t:ty;
        $($keys:ident( $vals:expr)),* $(,)?
    ) => {

        #[allow(unused)]
        #[repr($val_t)]
        $(#[derive($($derive_traits),+)])?
        $($visibility)? enum $name {
            $($keys = $vals,)*
        }

        use crate::error::{TlsError, TlsErrorCode};

        impl TryFrom<$val_t> for $name {
            type Error = TlsError;
            fn try_from(val: $val_t) -> Result<Self, TlsError> {
                match val {
                    $($vals => Ok(Self::$keys),)*
                    _ => Err( TlsError {
                        code: TlsErrorCode::ParseError,
                        msg: format!("Unspecified {} enum value: {}", stringify!($name), val),
                    }),
                }
            }
        }

    };
}

/// The `rfc_enum_no_err` declares an enum with a default value that implements
/// the [`From`] and [`Default`] trait.
///
/// # Example
/// ```rust
/// rfc_enum_no_err!{
///     [Eq, PartialEq, Debug]
///     (pub) MyEnum: u8;
///     [ReservedKey(0)], KeyA(1), KeyB(2),
/// };
/// # fn main() {
/// #   debug_assert_eq!(MyEnum::from(0), MyEnum::ReservedKey);
/// #   debug_assert_eq!(MyEnum::from(1), MyEnum::A);
/// #   debug_assert_eq!(MyEnum::from(2), MyEnum::B);
/// #   debug_assert_eq!(MyEnum::ReservedKey, MyEnum::default());
/// #   for i in 3..=u8::MAX {
/// #       debug_assert_eq!(MyEnum::from(i), MyEnum::default());
/// #   }
/// # }
/// ```
/// This macro will be expanded to:
/// ```rust
/// #[repr(u8)]
/// #[derive(Eq, PartialEq, Debug, Default)]
/// pub enum MyEnum {
///     KeyA = 1,
///     KeyB = 2,
///     #[default]
///     ReservedKey = 0,
/// }
/// impl From<u8> for MyEnum {
///     fn from(val: u8) -> Self {
///         match val {
///             1 => Self::KeyA,
///             2 => Self::KeyB,
///             _ => Self::ReservedKey,
///         }
///     }
/// }
/// ```
macro_rules! rfc_enum_no_err {
    (
        $([$($derive_traits:ident),+])?
        $(($visibility:vis))? $name:ident : $val_t:ty;
        [$default_key:ident$(( $default_val:expr) )?],
        $($keys:ident($vals:expr)),* $(,)?
    ) => {
        #[allow(unused)]
        #[repr($val_t)]
        $(#[derive($($derive_traits),+)])?
        #[derive(Default)]
        $($visibility)? enum $name {
            $($keys = $vals),*,
            #[default]
            $default_key $( = $default_val)?,
        }
        impl From<$val_t> for $name {
            fn from(val: $val_t) -> Self {
                match val {
                    $($vals => Self::$keys),*,
                    _ => Self::$default_key,
                }
            }
        }
    };
}

mod test {
    #[test]
    fn test_rfc_enum() {
        rfc_enum!(
            [Eq, PartialEq, Debug] (pub(self)) E: u8;
            A(1), B(2), C(3)
        );
        debug_assert_eq!(E::try_from(0).is_err(), true);
        debug_assert_eq!(E::try_from(1).unwrap(), E::A);
        debug_assert_eq!(E::try_from(2).unwrap(), E::B);
        debug_assert_eq!(E::try_from(3).unwrap(), E::C);
        for i in 4..=u8::MAX {
            debug_assert_eq!(E::try_from(i).is_err(), true);
        }
    }

    #[test]
    fn test_rfc_enum_no_err() {
        rfc_enum_no_err!(
            [Eq, PartialEq, Debug] (pub) E: u8;
            [Reserved(0)], A(1), B(2)
        );
        debug_assert_eq!(E::from(0), E::Reserved);
        debug_assert_eq!(E::from(1), E::A);
        debug_assert_eq!(E::from(2), E::B);
        for i in 3..=u8::MAX {
            debug_assert_eq!(E::from(i), E::Reserved);
        }
    }
}
