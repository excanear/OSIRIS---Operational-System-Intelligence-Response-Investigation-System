//! The ClickHouse HTTP transport: one worker thread owns the blocking
//! `reqwest` client and serves requests from a channel.
//!
//! Why a worker thread: `reqwest::blocking` panics when it is used (or its
//! client dropped) on a thread that is driving a tokio runtime. The server
//! calls `Storage` from async handlers, so callers here never touch
//! `reqwest` themselves — they send a [`Job`] and block on a plain
//! `std::sync::mpsc` reply channel, which is safe anywhere.
//!
//! No value is ever spliced into SQL text: scalars travel as `param_<name>`
//! URL parameters (`{name:Type}` placeholders), lists as external tables
//! (a `multipart/form-data` body), and inserted rows as a `JSONEachRow`
//! body.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use osiris_storage::StorageError;
use reqwest::Url;

/// How much of a ClickHouse error body is kept in a `StorageError`.
const ERROR_BODY_LIMIT: usize = 512;

/// A list of values sent as an external table (`<name>_structure`,
/// `<name>_format=TSV`). The table has exactly one column, declared by
/// `structure` (for example `"id String"`); every entry of `rows` is one
/// value of that column. Values are TSV-escaped here, not by the caller.
pub(crate) struct ExternalTable<'a> {
    pub name: &'a str,
    pub structure: &'a str,
    pub rows: Vec<String>,
}

/// One HTTP request handed to the worker thread.
struct Job {
    url: Url,
    content_type: Option<String>,
    body: Vec<u8>,
    reply: mpsc::Sender<Result<String, StorageError>>,
}

pub(crate) struct Transport {
    base: Url,
    database: String,
    user: String,
    password: Option<String>,
    timeout: Duration,
    jobs: mpsc::Sender<Job>,
}

impl Transport {
    /// Spawns the worker thread and waits until it has built its client.
    pub(crate) fn start(
        url: &str,
        database: &str,
        user: &str,
        password: Option<String>,
        timeout: Duration,
    ) -> Result<Self, StorageError> {
        let base = Url::parse(url)
            .map_err(|e| StorageError::Backend(format!("clickhouse: invalid url: {e}")))?;
        if base.scheme() != "http" && base.scheme() != "https" {
            return Err(StorageError::Backend(
                "clickhouse: url must be http:// or https://".to_string(),
            ));
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(StorageError::Backend(
                "clickhouse: credentials in the url are not allowed; use user/password_file"
                    .to_string(),
            ));
        }

        let (jobs, rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let user_header = user.to_string();
        let key_header = password.clone();
        thread::Builder::new()
            .name("osiris-clickhouse".to_string())
            .spawn(move || worker(rx, ready_tx, timeout, user_header, key_header))
            .map_err(|e| {
                StorageError::Backend(format!("clickhouse: cannot spawn worker thread: {e}"))
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(StorageError::Backend(format!(
                    "clickhouse: cannot build http client: {e}"
                )))
            }
            Err(_) => {
                return Err(StorageError::Backend(
                    "clickhouse: worker thread exited during startup".to_string(),
                ))
            }
        }

        Ok(Self {
            base,
            database: database.to_string(),
            user: user.to_string(),
            password,
            timeout,
            jobs,
        })
    }

    /// Runs `sql` in the configured database and returns the response body.
    ///
    /// `params` become `param_<name>` URL parameters. They are for **scalar
    /// values only**: each value is TSV-escaped, which is what ClickHouse
    /// expects for a scalar `{name:Type}`. A list must go through `tables`
    /// as an external table. Passing an `Array`/`Tuple` literal as a param
    /// would escape it a second time and corrupt it. `tables` turn the
    /// request into a multipart form with one part per external table.
    /// `body`, when given, is the data of an `INSERT ... FORMAT ...` query;
    /// the query then moves to the `query` URL parameter. `tables` and
    /// `body` are mutually exclusive.
    pub(crate) fn execute(
        &self,
        sql: &str,
        params: &[(&str, String)],
        tables: &[ExternalTable],
        body: Option<String>,
    ) -> Result<String, StorageError> {
        self.execute_in(Some(&self.database), sql, params, tables, body)
    }

    /// Like [`Transport::execute`], but without selecting a database — for
    /// `CREATE DATABASE` / `DROP DATABASE`, which must work when the
    /// database does not exist.
    pub(crate) fn execute_server(&self, sql: &str) -> Result<String, StorageError> {
        self.execute_in(None, sql, &[], &[], None)
    }

    fn execute_in(
        &self,
        database: Option<&str>,
        sql: &str,
        params: &[(&str, String)],
        tables: &[ExternalTable],
        body: Option<String>,
    ) -> Result<String, StorageError> {
        if !tables.is_empty() && body.is_some() {
            return Err(StorageError::Backend(
                "clickhouse: external tables and an insert body cannot be combined".to_string(),
            ));
        }
        let mut url = self.base.clone();
        let (content_type, payload) = {
            let mut q = url.query_pairs_mut();
            if let Some(db) = database {
                q.append_pair("database", db);
            }
            // Without this, an exception raised after the first blocks were
            // flushed arrives as HTTP 200 with a partial body and an
            // `__exception__` trailer (verified on 26.3). With it, the
            // server buffers the whole result and returns a real error
            // status. `send` also checks for the trailer, as a backstop.
            q.append_pair("wait_end_of_query", "1");
            for (name, value) in params {
                // ClickHouse parses a parameter value in its escaped (TSV)
                // text form: an unescaped tab or backslash cuts the value
                // short with BAD_QUERY_PARAMETER (verified on 26.3), so
                // every value is escaped. A no-op for numbers.
                q.append_pair(&format!("param_{name}"), &tsv_escape(value));
            }
            if let Some(rows) = body {
                q.append_pair("query", sql);
                (None, rows.into_bytes())
            } else if tables.is_empty() {
                (None, sql.as_bytes().to_vec())
            } else {
                for table in tables {
                    if !crate::is_valid_identifier(table.name) {
                        return Err(StorageError::Backend(format!(
                            "clickhouse: invalid external table name {:?}",
                            table.name
                        )));
                    }
                    q.append_pair(&format!("{}_structure", table.name), table.structure);
                    q.append_pair(&format!("{}_format", table.name), "TSV");
                }
                let (boundary, form) = multipart_body(sql, tables);
                (
                    Some(format!("multipart/form-data; boundary={boundary}")),
                    form,
                )
            }
        };

        let (reply, reply_rx) = mpsc::channel();
        let job = Job {
            url,
            content_type,
            body: payload,
            reply,
        };
        self.jobs.send(job).map_err(|_| {
            StorageError::Backend("clickhouse: worker thread is not running".to_string())
        })?;
        // No caller-side timeout: reqwest's timeout bounds every request, and
        // a job queued behind others must not be reported as failed while
        // it may still run later (an insert would then be applied after its
        // caller saw an error). The worker always replies, or drops the
        // reply sender if it dies, which ends this `recv` with an error.
        let result = match reply_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(StorageError::Backend(
                "clickhouse: worker thread exited without replying".to_string(),
            )),
        };
        result.map_err(|e| self.scrub(e))
    }

    /// Defence in depth: no error leaves the transport carrying the password.
    fn scrub(&self, err: StorageError) -> StorageError {
        let Some(pw) = self.password.as_deref().filter(|p| !p.is_empty()) else {
            return err;
        };
        match err {
            StorageError::Backend(m) => StorageError::Backend(m.replace(pw, "***")),
            StorageError::Serialize(m) => StorageError::Serialize(m.replace(pw, "***")),
        }
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("url", &self.base.as_str())
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

fn worker(
    jobs: mpsc::Receiver<Job>,
    ready: mpsc::Sender<Result<(), String>>,
    timeout: Duration,
    user: String,
    key: Option<String>,
) {
    let client = match reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
    {
        Ok(c) => {
            let _ = ready.send(Ok(()));
            c
        }
        Err(e) => {
            let _ = ready.send(Err(e.to_string()));
            return;
        }
    };
    // Ends when every `Transport` sender is dropped.
    while let Ok(job) = jobs.recv() {
        let mut req = client
            .post(job.url)
            .header("X-ClickHouse-User", &user)
            .body(job.body);
        if let Some(k) = key.as_deref() {
            req = req.header("X-ClickHouse-Key", k);
        }
        if let Some(ct) = job.content_type {
            req = req.header(reqwest::header::CONTENT_TYPE, ct);
        }
        let result = send(req);
        let _ = job.reply.send(result);
    }
}

fn send(req: reqwest::blocking::RequestBuilder) -> Result<String, StorageError> {
    let resp = req.send().map_err(|e| {
        // `without_url`: the URL carries query parameters, which are not
        // secret but are noise in an error message.
        StorageError::Backend(format!("clickhouse: request failed: {}", e.without_url()))
    })?;
    let status = resp.status();
    let exception = resp
        .headers()
        .get("X-ClickHouse-Exception-Code")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let exception_tag = resp
        .headers()
        .get("X-ClickHouse-Exception-Tag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let text = resp.text().map_err(|e| {
        StorageError::Backend(format!(
            "clickhouse: reading response failed: {}",
            e.without_url()
        ))
    })?;
    if !status.is_success() || exception.is_some() {
        return Err(StorageError::Backend(format!(
            "clickhouse: {}: {}",
            status,
            truncate(&text, ERROR_BODY_LIMIT)
        )));
    }
    if let Some(message) = exception_trailer(&text, exception_tag.as_deref()) {
        return Err(StorageError::Backend(format!(
            "clickhouse: {}: {}",
            status,
            truncate(message, ERROR_BODY_LIMIT)
        )));
    }
    Ok(text)
}

/// Backstop for an exception raised mid-stream (which `wait_end_of_query=1`
/// should already prevent). On 26.3 the body then ends with
/// `\n__exception__\n<tag>\n<message>\n<len> <tag>\n__exception__\n`, where
/// `<tag>` is the random `X-ClickHouse-Exception-Tag` response header, so a
/// data row cannot fake it. Returns the exception message if present.
fn exception_trailer<'a>(body: &'a str, tag: Option<&str>) -> Option<&'a str> {
    let tag = tag.filter(|t| !t.is_empty())?;
    let end_marker = format!("{tag}\n__exception__");
    let trimmed = body.trim_end_matches('\n');
    if !trimmed.ends_with(&end_marker) {
        return None;
    }
    let start_marker = format!("__exception__\n{tag}\n");
    let start = trimmed.rfind(&start_marker)? + start_marker.len();
    let message = &trimmed[start..trimmed.len() - end_marker.len()];
    // Drop the trailing `<len> ` length field.
    let message = message.trim_end();
    let message = message
        .rsplit_once('\n')
        .map(|(m, _len)| m)
        .unwrap_or(message);
    Some(message.trim())
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Escapes one value for ClickHouse's `TSV` input format.
pub(crate) fn tsv_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            other => out.push(other),
        }
    }
    out
}

/// Builds the `multipart/form-data` body: a `query` part with the SQL text
/// and one file part per external table. Returns `(boundary, body)`.
fn multipart_body(sql: &str, tables: &[ExternalTable]) -> (String, Vec<u8>) {
    let mut table_data: Vec<String> = Vec::with_capacity(tables.len());
    for table in tables {
        let mut data = String::new();
        for row in &table.rows {
            data.push_str(&tsv_escape(row));
            data.push('\n');
        }
        table_data.push(data);
    }
    // A random boundary that occurs in no part (re-rolled on the
    // astronomically unlikely collision).
    let boundary = loop {
        let b = format!("osiris-{}", uuid::Uuid::new_v4().simple());
        if !sql.contains(&b) && table_data.iter().all(|d| !d.contains(&b)) {
            break b;
        }
    };

    let mut body = String::new();
    body.push_str(&format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"query\"\r\n\r\n{sql}\r\n"
    ));
    for (table, data) in tables.iter().zip(&table_data) {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{name}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n{data}\r\n",
            name = table.name
        ));
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    (boundary, body.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_body_has_query_and_one_part_per_table() {
        let tables = [ExternalTable {
            name: "ids",
            structure: "id String",
            rows: vec!["a".to_string(), "b\tc".to_string()],
        }];
        let (boundary, body) = multipart_body("SELECT 1", &tables);
        let body = String::from_utf8(body).unwrap();
        assert!(body.starts_with(&format!("--{boundary}\r\n")));
        assert!(body.contains("name=\"query\"\r\n\r\nSELECT 1\r\n"));
        assert!(body.contains("name=\"ids\"; filename=\"ids\""));
        assert!(body.contains("\r\n\r\na\nb\\tc\n\r\n"));
        assert!(body.ends_with(&format!("--{boundary}--\r\n")));
    }

    #[test]
    fn exception_trailer_is_detected_only_with_the_matching_tag() {
        // The shape ClickHouse 26.3 emits after a mid-stream exception.
        let body = "95\t0\n99999\t0\n\n__exception__\noeaqwyeogsepvaad\n\
                    Code: 395. DB::Exception: boom. (FUNCTION_THROW_IF_VALUE_IS_NON_ZERO)\n\
                    291 oeaqwyeogsepvaad\n__exception__\n";
        assert_eq!(
            exception_trailer(body, Some("oeaqwyeogsepvaad")),
            Some("Code: 395. DB::Exception: boom. (FUNCTION_THROW_IF_VALUE_IS_NON_ZERO)")
        );
        assert_eq!(exception_trailer(body, Some("othertagxxxxxxxx")), None);
        assert_eq!(exception_trailer(body, None), None);
        assert_eq!(exception_trailer("1\n2\n", Some("oeaqwyeogsepvaad")), None);
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("aé", 2), "a");
    }
}
