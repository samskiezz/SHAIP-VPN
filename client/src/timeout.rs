//! Await a future with a labelled timeout.

use anyhow::{anyhow, Result};
use std::future::Future;
use std::time::Duration;

pub async fn with_timeout<F, T>(label: &'static str, secs: u64, fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match tokio::time::timeout(Duration::from_secs(secs), fut).await {
        Ok(res) => res,
        Err(_) => Err(anyhow!("{label} timed out after {secs}s")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn returns_on_timeout() {
        let r: Result<()> = with_timeout("test", 1, async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        })
        .await;
        assert!(r.is_err());
    }
}
