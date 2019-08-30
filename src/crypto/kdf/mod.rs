use ffi;
// use libc::c_ulonglong;
use randombytes::randombytes_into;

/// Minimum number of bytes in a derived key
pub const DERIVED_KEY_BYTES_MIN: usize = ffi::crypto_kdf_blake2b_BYTES_MIN as usize;

/// Maximum number of bytes in a derived key
pub const DERIVED_KEY_BYTES_MAX: usize = ffi::crypto_kdf_blake2b_BYTES_MAX as usize;

/// Number of bytes in a `MasterKey`
pub const MASTER_KEY_BYTES: usize = ffi::crypto_kdf_blake2b_KEYBYTES as usize;

/// Number of bytes in a `Context`
pub const CONTEXT_BYTES: usize = ffi::crypto_kdf_blake2b_CONTEXTBYTES as usize;

new_type! {
    /// `MasterKey` used for key derivation.
    public MasterKey(MASTER_KEY_BYTES);
}

/// Generates a random `MasterKey`.
pub fn generate_key() -> MasterKey {
    let mut key = [0; MASTER_KEY_BYTES];
    randombytes_into(&mut key);
    MasterKey(key)
}

/// Generates a random `Context`.
pub fn generate_context() -> Context {
    let mut context = [0; CONTEXT_BYTES];
    randombytes_into(&mut context);
    Context(context)
}

new_type! {
    /// `Context` used for key derivation. It doesn't have to be secret and can be low entropy.
    public Context(CONTEXT_BYTES);
}

/// A session for generating keys
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Session {
    index: u64,
    context: Context,
    key: MasterKey,
}

impl Session {
    /// Attempts to fill `buffer` with the next key in the sequence.
    /// Returns `None` if `buffer` is shorter than `DERIVED_KEY_BYTES_MIN` or longer than
    /// `DERIVED_KEY_BYTES_MAX`, or if `libsodium` returned an error.
    /// Otherwise returns `Some(i)` where `i` is the index used to fill `buffer`.
    pub fn generate_next_key(&mut self, buffer: &mut [u8]) -> Option<u64> {
        let len = buffer.len();
        if len < DERIVED_KEY_BYTES_MIN || DERIVED_KEY_BYTES_MAX < len {
            return None;
        }
        let i = unsafe {
            let subkey: *mut libc::c_uchar = std::mem::transmute(buffer.as_mut_ptr());
            let ctx: *const libc::c_char = std::mem::transmute(self.context.as_ref().as_ptr());
            let key: *const libc::c_uchar = std::mem::transmute(self.key.as_ref().as_ptr());
            ffi::crypto_kdf_blake2b_derive_from_key(subkey, len, self.index, ctx, key)
        };
        self.index += 1;
        if i == 0 {
            Some(self.index - 1)
        } else {
            None
        }
    }
}

/// A builder for `Session`s.
pub struct SessionBuilder {
    index: Option<u64>,
    context: Option<Context>,
    key: Option<MasterKey>,
}

impl SessionBuilder {
    /// Creates a new `SessionBuilder`.
    pub fn new() -> Self {
        SessionBuilder {
            index: None,
            context: None,
            key: None,
        }
    }

    /// Sets the index of a `SessionBuilder`, overriding one if it was already set.
    pub fn index(&mut self, i: u64) -> &mut Self {
        self.index = Some(i);
        self
    }

    /// Sets the key of a `SessionBuilder`, overriding one if it was already set.
    pub fn key(&mut self, key: MasterKey) -> &mut Self {
        self.key = Some(key);
        self
    }

    /// Sets the key of a `SessionBuilder` to a random value, overriding one if it was already set.
    pub fn random_key(&mut self) -> &mut Self {
        self.key(generate_key())
    }

    /// Sets the context of a `SessionBuilder`, overriding one if it was already set.
    pub fn context(&mut self, context: Context) -> &mut Self {
        self.context = Some(context);
        self
    }

    /// Sets the context of a `SessionBuilder` to a random value, overriding one if it was already set.
    pub fn random_context(&mut self) -> &mut Self {
        self.context(generate_context())
    }

    /// Attempts to build a session from a builder, filling in a default context and index if they
    /// were not specified.
    pub fn build(&self) -> Option<Session> {
        let SessionBuilder {
            index: maybe_index,
            context: maybe_context,
            key: maybe_key,
        } = self;
        let index = maybe_index.unwrap_or_else(|| 0);
        let context = maybe_context.unwrap_or_else(|| Context([0; 8]));
        let key = maybe_key.as_ref()?.clone();
        Some(Session {
            index,
            context,
            key,
        })
    }

    /// Attempts to build a session from a builder and fails if not all fields are present with
    /// bools indicating which were missing.
    /// Bool array returns `true` if the field was missing, `false` if it was present.
    /// The order for fields in the array is `index`, `context`, `key`.
    pub fn build_full(&self) -> Result<Session, [bool; 3]> {
        let outs = [
            self.index.is_none(),
            self.context.is_none(),
            self.key.is_none(),
        ];
        match (&self.index, &self.context, &self.key) {
            (None, _, _) | (_, None, _) | (_, _, None) => Err(outs),
            _ => Ok(self.build().unwrap()),
        }
    }
}

const SESSION_TYPE_STRING: &'static str = stringify!(Session);
const SESSION_INDEX_STRING: &'static str = "index";
const SESSION_CONTEXT_STRING: &'static str = "context";
const SESSION_KEY_STRING: &'static str = "key";
const SESSION_FIELDS_ARRAY: &'static [&'static str] = &[SESSION_KEY_STRING, SESSION_INDEX_STRING];

// ser and de implemented by hand because the macro would be as much of a mess as serde_derive
#[cfg(feature = "serde")]
impl ::serde::Serialize for Session {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut ser = serializer.serialize_struct(SESSION_TYPE_STRING, 2)?;
        ser.serialize_field(SESSION_INDEX_STRING, &self.index)?;
        ser.serialize_field(SESSION_CONTEXT_STRING, &self.context)?;
        ser.serialize_field(SESSION_KEY_STRING, &self.key)?;
        ser.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Session {
    fn deserialize<D>(deserializer: D) -> Result<Session, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        struct StructVisitor;
        impl<'de> ::serde::de::Visitor<'de> for StructVisitor {
            type Value = Session;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "{}", SESSION_TYPE_STRING)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: ::serde::de::MapAccess<'de>,
            {
                let mut builder = SessionBuilder::new();
                // consider throwing an error if we see the same key twice?
                for _ in 0..3 {
                    let mapkey: &str = map.next_key()?.ok_or(
                        ::serde::de::Error::invalid_length(SESSION_FIELDS_ARRAY.len(), &self),
                    )?;
                    if mapkey == SESSION_INDEX_STRING {
                        builder.index(map.next_value()?);
                    } else if mapkey == SESSION_CONTEXT_STRING {
                        builder.context(map.next_value()?);
                    } else if mapkey == SESSION_KEY_STRING {
                        builder.key(map.next_value()?);
                    } else {
                        return Err(::serde::de::Error::unknown_field(
                            mapkey,
                            SESSION_FIELDS_ARRAY,
                        ));
                    }
                }
                builder.build_full().map_err(|missing_bools| {
                    let missing = if missing_bools[0] {
                        "index"
                    } else if missing_bools[1] {
                        "context"
                    } else if missing_bools[2] {
                        "key"
                    } else {
                        panic!(
                            "sodiumoxide: this should never happen, error in {} line {}",
                            file!(),
                            line!()
                        )
                    };
                    ::serde::de::Error::missing_field(missing)
                })
            }
        }
        deserializer.deserialize_struct(SESSION_TYPE_STRING, SESSION_FIELDS_ARRAY, StructVisitor)
    }
}
