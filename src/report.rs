use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

pub fn generate_report_id() -> Result<String, SystemTimeError> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    Ok(format!("SOC-{seconds}"))
}

pub fn generate_timestamp() -> Result<u64, SystemTimeError> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    Ok(seconds)
}

#[cfg(test)]
mod tests {

    #[test]
    fn generates_valid_timestamp() {
        let result = super::generate_timestamp();

        assert!(result.is_ok());

        if let Ok(timestamp) = result {
            assert!(timestamp > 0);
        }
    }
}
