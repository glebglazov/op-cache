use std::collections::HashSet;
use std::io::{self, Read, Write};

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::Result;

/// What a concealed secret is replaced with. Same shape as `op run`'s marker so
/// output stays recognisable, but named after the tool that did the work.
const REPLACEMENT: &[u8] = b"<concealed by op-cache>";

/// Values shorter than this are left alone. A secret whose value is `true` or a
/// port number appears all over unrelated output, and concealing those turns a
/// leak guard into noise the user will want to switch off.
const MIN_SECRET_LEN: usize = 8;

const CHUNK: usize = 8 * 1024;

/// The strings worth concealing, drawn from the resolved secret values.
///
/// A multi-line secret contributes its lines as well as the whole value: a tool
/// printing a private key emits it one line at a time, and no single line it
/// writes ever equals the value as a whole.
pub fn patterns<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut patterns = Vec::new();

    for value in values {
        for candidate in std::iter::once(value).chain(value.lines()) {
            let candidate = candidate.trim();
            if !is_maskable(candidate) {
                continue;
            }
            if seen.insert(candidate) {
                patterns.push(candidate.to_string());
            }
        }
    }

    patterns
}

fn is_maskable(value: &str) -> bool {
    value.len() >= MIN_SECRET_LEN && !value.bytes().all(|b| b.is_ascii_digit())
}

/// Rewrites a child process's output with every known secret concealed.
pub struct Masker {
    ac: AhoCorasick,
    replacements: Vec<&'static [u8]>,
    /// Patterns sorted so a candidate tail can be prefix-matched by binary
    /// search instead of a scan.
    sorted: Vec<Vec<u8>>,
    /// Which bytes any pattern starts with. A match can only begin at one of
    /// these, which is what keeps the per-chunk holdback scan linear.
    starts: [bool; 256],
    longest: usize,
}

impl Masker {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(patterns)?;

        let mut sorted: Vec<Vec<u8>> = patterns.iter().map(|p| p.as_bytes().to_vec()).collect();
        sorted.sort();

        let mut starts = [false; 256];
        for pattern in &sorted {
            starts[pattern[0] as usize] = true;
        }

        Ok(Self {
            ac,
            replacements: vec![REPLACEMENT; patterns.len()],
            longest: sorted.iter().map(|p| p.len()).max().unwrap_or(0),
            sorted,
            starts,
        })
    }

    /// Copies `rdr` to `wtr`, concealing secrets on the way.
    ///
    /// Output is flushed as it arrives, minus any trailing bytes that could
    /// still grow into a secret, so an interactive child keeps feeling
    /// interactive while a secret split across two reads is still caught.
    pub fn filter<R: Read, W: Write>(&self, mut rdr: R, mut wtr: W) -> io::Result<()> {
        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = [0u8; CHUNK];

        loop {
            let read = match rdr.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // The pty master reports EIO once the child side is gone. For
                // a caller that is EOF, not a failure.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => return Err(e),
            };
            pending.extend_from_slice(&chunk[..read]);

            let emit = pending.len() - self.holdback(&pending);
            if emit > 0 {
                wtr.write_all(&self.conceal(&pending[..emit]))?;
                wtr.flush()?;
                pending.drain(..emit);
            }
        }

        if !pending.is_empty() {
            wtr.write_all(&self.conceal(&pending))?;
        }
        wtr.flush()
    }

    fn conceal(&self, bytes: &[u8]) -> Vec<u8> {
        self.ac.replace_all_bytes(bytes, &self.replacements)
    }

    /// Length of the trailing run of `buf` that must be withheld, measured from
    /// the earliest position where a secret could have begun. Zero whenever
    /// nothing at the end of the buffer has started to look like one.
    ///
    /// Taking the earliest such position, rather than the first one found, is
    /// what keeps a long secret intact: a value that is only partly in the
    /// buffer must not be cut where a shorter secret happens to end.
    fn holdback(&self, buf: &[u8]) -> usize {
        let max = self.longest.min(buf.len());

        for len in (1..=max).rev() {
            let tail = &buf[buf.len() - len..];
            if !self.starts[tail[0] as usize] {
                continue;
            }
            if self.starts_a_secret(tail) {
                return len;
            }
        }

        0
    }

    /// True when `tail` is how one of the secrets begins, whether or not it is
    /// yet the whole of it. A tail that is already a whole secret is still held
    /// back: the next read may extend it into a longer one.
    fn starts_a_secret(&self, tail: &[u8]) -> bool {
        let at = match self.sorted.binary_search_by(|p| p.as_slice().cmp(tail)) {
            Ok(at) => at,
            Err(at) => at,
        };
        self.sorted
            .get(at)
            .is_some_and(|pattern| pattern.starts_with(tail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masker(patterns: &[&str]) -> Masker {
        let patterns: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
        Masker::new(&patterns).unwrap()
    }

    /// A reader that hands out one slice per `read`, so a filter has to cope
    /// with secrets straddling the boundary between them.
    struct Chunks(Vec<Vec<u8>>);

    impl Read for Chunks {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Ok(0);
            }
            let chunk = self.0.remove(0);
            buf[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    fn filter_chunks(masker: &Masker, chunks: &[&str]) -> String {
        let reader = Chunks(chunks.iter().map(|c| c.as_bytes().to_vec()).collect());
        let mut out = Vec::new();
        masker.filter(reader, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn conceals_a_secret_split_across_reads() {
        let masker = masker(&["hunter2hunter2"]);
        let out = filter_chunks(&masker, &["token=hunter2", "hunter2 done\n"]);
        assert_eq!(out, "token=<concealed by op-cache> done\n");
    }

    #[test]
    fn conceals_every_occurrence_in_one_read() {
        let masker = masker(&["s3cret-value"]);
        let out = filter_chunks(&masker, &["a s3cret-value and s3cret-value again"]);
        assert_eq!(
            out,
            "a <concealed by op-cache> and <concealed by op-cache> again"
        );
    }

    #[test]
    fn conceals_the_longest_secret_when_one_contains_another() {
        // A connection string holding its own password is the real case: both
        // are secrets, and concealing the password alone would leave the rest
        // of the URL in the log.
        let masker = masker(&["passw0rd!", "postgres://u:passw0rd!@db/app"]);
        let out = filter_chunks(&masker, &["url=postgres://u:passw0rd!@db/app"]);
        assert_eq!(out, "url=<concealed by op-cache>");
    }

    #[test]
    fn passes_output_through_before_the_stream_ends() {
        // Nothing at the end of the first read looks like the secret, so it
        // must not be withheld waiting for more input.
        let masker = masker(&["hunter2hunter2"]);
        let reader = Chunks(vec![b"prompt> ".to_vec()]);
        let mut out = Vec::new();
        masker.filter(reader, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "prompt> ");
    }

    #[test]
    fn holds_back_only_what_could_still_become_a_secret() {
        let masker = masker(&["hunter2hunter2"]);
        assert_eq!(masker.holdback(b"log line hunter2h"), 8);
        assert_eq!(masker.holdback(b"log line"), 0);
        // A whole secret at the end is withheld too, in case more of it is
        // still to come.
        assert_eq!(masker.holdback(b"log line hunter2hunter2"), 14);
    }

    #[test]
    fn patterns_include_each_line_of_a_multi_line_secret() {
        let key = "-----BEGIN KEY-----\nabcdefghijkl\n-----END KEY-----";
        let patterns = patterns(std::iter::once(key));
        assert!(patterns.contains(&key.to_string()));
        assert!(patterns.contains(&"abcdefghijkl".to_string()));
    }

    #[test]
    fn patterns_skip_values_too_short_or_too_plain_to_conceal() {
        let values = vec!["true", "8080", "5432", "short"];
        assert!(patterns(values.into_iter()).is_empty());
    }

    #[test]
    fn patterns_deduplicate_a_single_line_value() {
        assert_eq!(patterns(std::iter::once("s3cret-value")).len(), 1);
    }
}
