//! Secret input: hidden terminal prompts, or lines from standard input with
//! `--password-stdin`. Secrets are never accepted as command-line arguments
//! (they would be visible in process lists and shell history).

use std::io::{BufRead, StdinLock};

use lk_crypto::Zeroizing;

use crate::error::{Result, fail};

pub(crate) struct SecretInput {
    stdin: Option<StdinLock<'static>>,
}

impl SecretInput {
    pub(crate) fn new(from_stdin: bool) -> Self {
        Self {
            stdin: from_stdin.then(|| std::io::stdin().lock()),
        }
    }

    /// Reads one secret. With `--password-stdin`, one line per secret, in the
    /// order the command asks for them.
    pub(crate) fn read(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        match &mut self.stdin {
            Some(stdin) => {
                // Pre-allocated so typical secrets never trigger a reallocation
                // that would leave an unzeroized copy behind.
                let mut line = Zeroizing::new(String::with_capacity(4096));
                let read = stdin.read_line(&mut line)?;
                if read == 0 {
                    return Err(fail(format!(
                        "expected a line on standard input for: {}",
                        prompt.trim_end_matches([':', ' '])
                    )));
                }
                while line.ends_with('\n') || line.ends_with('\r') {
                    line.pop();
                }
                Ok(line)
            }
            None => Ok(Zeroizing::new(rpassword::prompt_password(prompt)?)),
        }
    }

    /// Reads a new secret twice and checks both entries match.
    pub(crate) fn read_confirmed(
        &mut self,
        prompt: &str,
        confirm: &str,
    ) -> Result<Zeroizing<String>> {
        let first = self.read(prompt)?;
        let second = self.read(confirm)?;
        if *first != *second {
            return Err(fail("the two entries do not match"));
        }
        Ok(first)
    }
}
