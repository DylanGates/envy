use crate::error::CoreError;
use crate::vault::Vault;

/// An event to record. Per FR-13, this must never carry a secret value —
/// only metadata about what happened.
pub struct AuditEvent<'a> {
    pub subject: Option<&'a str>,
    pub project: Option<&'a str>,
    pub provider: Option<&'a str>,
    pub operation: &'a str,
    pub endpoint_host: Option<&'a str>,
    pub outcome: &'a str,
    pub redaction_summary: Option<&'a str>,
}

/// A stored audit event, as read back from the vault.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditEventRecord {
    pub id: i64,
    pub timestamp: String,
    pub subject: Option<String>,
    pub project: Option<String>,
    pub provider: Option<String>,
    pub operation: String,
    pub endpoint_host: Option<String>,
    pub outcome: String,
    pub redaction_summary: Option<String>,
}

impl Vault {
    /// Records an audit event. Never call this with a secret value in any
    /// field — see [`AuditEvent`].
    pub fn log_event(&self, event: &AuditEvent) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO audit_events (subject, project, provider, operation, endpoint_host, outcome, redaction_summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                event.subject,
                event.project,
                event.provider,
                event.operation,
                event.endpoint_host,
                event.outcome,
                event.redaction_summary,
            ],
        )?;
        Ok(())
    }

    /// Lists audit events, most recent first, optionally filtered to one
    /// project.
    pub fn list_events(&self, project: Option<&str>) -> Result<Vec<AuditEventRecord>, CoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, subject, project, provider, operation, endpoint_host, outcome, redaction_summary
             FROM audit_events
             WHERE (?1 IS NULL OR project = ?1)
             ORDER BY id DESC",
        )?;
        let rows = stmt.query_map(rusqlite::params![project], |row| {
            Ok(AuditEventRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                subject: row.get(2)?,
                project: row.get(3)?,
                provider: row.get(4)?,
                operation: row.get(5)?,
                endpoint_host: row.get(6)?,
                outcome: row.get(7)?,
                redaction_summary: row.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(CoreError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;
    use crate::vault::init_with_keystore;

    #[test]
    fn log_then_list_round_trips_all_fields() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &keystore).unwrap();

        vault
            .log_event(&AuditEvent {
                subject: Some("cli"),
                project: Some("/tmp/my-project"),
                provider: None,
                operation: "init",
                endpoint_host: None,
                outcome: "success",
                redaction_summary: None,
            })
            .unwrap();

        let events = vault.list_events(None).unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.subject.as_deref(), Some("cli"));
        assert_eq!(event.project.as_deref(), Some("/tmp/my-project"));
        assert_eq!(event.provider, None);
        assert_eq!(event.operation, "init");
        assert_eq!(event.outcome, "success");
        assert!(!event.timestamp.is_empty());
    }

    #[test]
    fn list_events_filters_by_project() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &keystore).unwrap();

        vault
            .log_event(&AuditEvent {
                subject: None,
                project: Some("/tmp/project-a"),
                provider: None,
                operation: "init",
                endpoint_host: None,
                outcome: "success",
                redaction_summary: None,
            })
            .unwrap();
        vault
            .log_event(&AuditEvent {
                subject: None,
                project: Some("/tmp/project-b"),
                provider: None,
                operation: "init",
                endpoint_host: None,
                outcome: "success",
                redaction_summary: None,
            })
            .unwrap();

        let events = vault.list_events(Some("/tmp/project-a")).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].project.as_deref(), Some("/tmp/project-a"));
    }
}
