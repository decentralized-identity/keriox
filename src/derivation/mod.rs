pub mod attached_signature_code;
pub mod basic;
pub mod self_addressing;
pub mod self_signing;

pub trait DerivationCode {
    fn code_len(&self) -> usize;
    fn derivative_b64_len(&self) -> usize;
    fn prefix_b64_len(&self) -> usize {
        self.code_len() + self.derivative_b64_len()
    }
    fn to_str(&self) -> String;
}
