use serde::Serialize;
use serde_json::Error as SerdeError;
use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Debug)]
pub enum ErrorHolderError {
    TooLarge(usize),
    Serde(SerdeError),
}

type Result<T> = std::result::Result<T, ErrorHolderError>;

// TODO: evolve this into an event holder.
// Record import or critical events or errors in this Holder so they can be collected.
/// It's not necessary to make this lock-less now
#[derive(Serialize, Default, Debug)]
pub struct ErrorHolder {
    max_errors: usize,
    total_errors: usize,
    max_size: usize,
    total_size: usize,
    errors: Mutex<VecDeque<String>>,
}

impl ErrorHolder {
    pub fn init(max_errors: usize, max_size: usize) -> Self {
        Self {
            max_errors,
            max_size,
            total_errors: 0,
            total_size: 0,
            errors: Mutex::new(VecDeque::with_capacity(max_errors)),
        }
    }

    pub fn push(&mut self, error: &str) -> Result<()> {
        let mut guard = self.errors.lock().unwrap();
        let formatted_error = format!("{:?} - {}", chrono::Local::now(), error);

        loop {
            if formatted_error.len() + self.total_size > self.max_size
                || self.total_errors >= self.max_errors
            {
                let victim = guard.pop_front();
                match victim {
                    Some(v) => {
                        self.total_size -= v.len();
                        self.total_errors -= 1;
                    }
                    None => return Err(ErrorHolderError::TooLarge(error.len())),
                }
            } else {
                break;
            }
        }

        self.total_size += formatted_error.len();
        self.total_errors += 1;
        guard.push_back(formatted_error);
        Ok(())
    }

    pub fn export(&self) -> Result<String> {
        let _guard = self.errors.lock().unwrap();
        serde_json::to_string(self).map_err(ErrorHolderError::Serde)
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorHolder, ErrorHolderError};

    #[test]
    fn test_overflow() {
        let mut holder = ErrorHolder::init(10, 80);
        let error_msg = "123456789";
        let mut left = 16;
        while left >= 0 {
            let r = holder.push(error_msg);
            assert_eq!(r.is_ok(), true);
            left -= 1;
        }

        assert_eq!(holder.total_errors <= 10, true);
        assert_eq!(holder.total_size <= 80, true);

        let mut multi = 10;
        let mut error_msg_long = "".to_string();
        while multi >= 0 {
            multi -= 1;
            error_msg_long.push_str("123456789");
        }

        let r = holder.push(&error_msg_long);
        match r {
            Err(ErrorHolderError::TooLarge(len)) => assert_eq!(len, error_msg_long.len()),
            _ => panic!(),
        }
    }
}
