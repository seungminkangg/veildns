pub mod config;
pub mod dns;
pub mod proxy;
pub mod tls;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn error(message: &'static str) -> BoxError {
    std::io::Error::other(message).into()
}
