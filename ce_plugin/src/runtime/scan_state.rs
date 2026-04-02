#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanValueKind {
    Byte,
    Word,
    Dword,
    Qword,
    Float,
    Double,
    String,
    Array,
}

impl ScanValueKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Byte => "byte",
            Self::Word => "word",
            Self::Dword => "dword",
            Self::Qword => "qword",
            Self::Float => "float",
            Self::Double => "double",
            Self::String => "string",
            Self::Array => "array",
        }
    }

    pub fn supports_numeric_ordering(&self) -> bool {
        matches!(
            self,
            Self::Byte | Self::Word | Self::Dword | Self::Qword | Self::Float | Self::Double
        )
    }
}

#[derive(Debug, Clone)]
pub struct ScanEntry {
    pub address: usize,
    pub value_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ScanSession {
    pub kind: ScanValueKind,
    pub entries: Vec<ScanEntry>,
}
