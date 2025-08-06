use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReferenceValue {
    pub name: String,
    pub expired: String,
    pub hash_value: ReferenceHashValue,
}

#[derive(Serialize)]
pub struct ReferenceHashValue {
    pub alg: String,
    pub value: String,
}
