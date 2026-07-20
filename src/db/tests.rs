use super::*;
use crate::model::DnsRecord;

fn assert_passive_deadline<T: std::fmt::Debug>(result: Result<T>) {
    let error = result.unwrap_err();
    assert!(
        is_passive_persistence_deadline_error(&error),
        "erreur inattendue: {error:#}"
    );
}

#[test]
fn passive_source_preflight_reads_do_not_wait_past_the_shared_deadline() {
    let db = Database::in_memory().unwrap();
    let shared_lock = db.lock().unwrap();
    let started = Instant::now();

    assert_passive_deadline(db.source_metadata_until(
        "fixture",
        Duration::from_secs(60),
        Instant::now() + Duration::from_millis(20),
    ));
    assert_passive_deadline(db.source_diagnostics_until(
        Duration::from_secs(60),
        Instant::now() + Duration::from_millis(20),
    ));
    assert_passive_deadline(db.source_cooldowns_until(
        Duration::from_secs(60),
        Instant::now() + Duration::from_millis(20),
    ));
    assert_passive_deadline(db.source_scores_until(Instant::now() + Duration::from_millis(20)));
    assert_passive_deadline(
        db.prior_candidates_until(10, Instant::now() + Duration::from_millis(20)),
    );

    assert!(
        started.elapsed() < Duration::from_secs(1),
        "les lectures de préparation ont dépassé leur échéance: {:?}",
        started.elapsed()
    );
    drop(shared_lock);
}

#[test]
fn bounded_observation_names_are_sorted_and_deduplicated_after_indexed_read() {
    let db = Database::in_memory().unwrap();
    db.store_observations(
        "example.com",
        vec![
            ObservationInput {
                fqdn: "z.example.com".to_owned(),
                kind: "passive".to_owned(),
                source: "passive:fixture".to_owned(),
                value: "first".to_owned(),
            },
            ObservationInput {
                fqdn: "a.example.com".to_owned(),
                kind: "passive".to_owned(),
                source: "passive:fixture".to_owned(),
                value: String::new(),
            },
            ObservationInput {
                fqdn: "z.example.com".to_owned(),
                kind: "passive".to_owned(),
                source: "passive:fixture".to_owned(),
                value: "second".to_owned(),
            },
        ],
    )
    .unwrap();

    assert_eq!(
        db.observation_names_bounded_until(
            "example.com",
            "passive:fixture",
            2,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap(),
        vec!["a.example.com", "z.example.com"]
    );

    let connection = db.lock().unwrap();
    let mut statement = connection
        .prepare(
            r#"EXPLAIN QUERY PLAN
               SELECT e.name_id, n.fqdn FROM observation_evidence e
               JOIN observed_names n ON n.id=e.name_id
               WHERE e.root_domain=?1 AND e.source=?2 AND e.name_id>?3
               ORDER BY e.name_id LIMIT ?4"#,
        )
        .unwrap();
    let plan = statement
        .query_map(
            params!["example.com", "passive:fixture", 0_i64, 2_i64],
            |row| row.get::<_, String>(3),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|detail| detail.contains("idx_observation_root_source")),
        "le plan doit parcourir l'index root/source/name_id: {plan:?}"
    );
    assert!(
        plan.iter()
            .all(|detail| !detail.contains("TEMP B-TREE FOR ORDER BY")),
        "le plan ne doit pas trier toutes les observations: {plan:?}"
    );
}

#[test]
fn bounded_legacy_passive_cache_reads_until_the_unique_name_limit() {
    let db = Database::in_memory().unwrap();
    db.lock()
        .unwrap()
        .execute(
            r#"INSERT INTO passive_cache(root_domain, source, names_json, updated_at)
               VALUES (?1, ?2, ?3, ?4)"#,
            params![
                "example.com",
                "legacy",
                r#"["dup.example.com","dup.example.com","api.example.com","z.example.com"]"#,
                now_epoch()
            ],
        )
        .unwrap();

    let cached = db
        .passive_cache_bounded_until(
            "example.com",
            "legacy",
            2,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();

    assert_eq!(
        cached.names,
        vec!["api.example.com".to_owned(), "dup.example.com".to_owned()]
    );
}

#[test]
fn observation_writer_reply_received_before_deadline_succeeds() {
    let (reply, response) = mpsc::channel();
    let expected = ObservationWriteStats {
        written: 7,
        novel_names: 3,
    };
    reply.send(Ok(expected)).unwrap();

    let actual =
        receive_observation_writer_reply(response, Some(Instant::now() + Duration::from_secs(1)))
            .unwrap();

    assert_eq!(actual, expected);
}

#[test]
fn observation_writer_reply_respects_deadline_when_reply_is_withheld() {
    let (_reply, response) = mpsc::channel::<Result<ObservationWriteStats>>();
    let started = Instant::now();

    let error =
        receive_observation_writer_reply(response, Some(started + Duration::from_millis(25)))
            .unwrap_err();

    assert_eq!(
        error.to_string(),
        "délai de persistance SQLite passive dépassé"
    );
    assert!(is_passive_persistence_deadline_error(&error));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "le timeout du writer a pris {:?}",
        started.elapsed()
    );
}

#[test]
fn observation_writer_reply_reports_disconnected_channel() {
    let (reply, response) = mpsc::channel::<Result<ObservationWriteStats>>();
    drop(reply);

    let error =
        receive_observation_writer_reply(response, Some(Instant::now() + Duration::from_secs(1)))
            .unwrap_err();

    assert_eq!(error.to_string(), "réponse du writer SQLite absente");
    assert!(!is_passive_persistence_deadline_error(&error));
}

#[test]
fn passive_observation_page_rejects_an_expired_persistence_deadline() {
    let db = Database::in_memory().unwrap();
    let names = BTreeSet::from(["api.example.com".to_owned()]);
    let deadline = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap();

    let error = db
        .store_passive_observation_page_until("example.com", "fixture", &names, deadline)
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "délai de persistance SQLite passive dépassé"
    );
    assert!(is_passive_persistence_deadline_error(&error));
    assert!(
        db.observation_names("example.com", "passive:fixture")
            .unwrap()
            .is_empty(),
        "une page arrivée après l'échéance ne doit rien persister"
    );
}

#[test]
fn passive_observation_page_does_not_wait_past_deadline_for_shared_lock() {
    let db = Database::in_memory().unwrap();
    let shared_lock = db.lock().unwrap();
    let worker_db = db.clone();
    let started = Instant::now();

    let worker = std::thread::spawn(move || {
        worker_db.store_passive_observation_page_until(
            "example.com",
            "fixture",
            &BTreeSet::from(["api.example.com".to_owned()]),
            Instant::now() + Duration::from_millis(50),
        )
    });
    let error = worker.join().unwrap().unwrap_err();

    assert_eq!(
        error.to_string(),
        "délai de persistance SQLite passive dépassé"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "l'attente du verrou a dépassé la borne: {:?}",
        started.elapsed()
    );
    drop(shared_lock);
    assert!(
        db.observation_names("example.com", "passive:fixture")
            .unwrap()
            .is_empty(),
        "un timeout de verrou ne doit laisser aucune observation partielle"
    );
}

#[test]
fn deadline_aware_numeric_passive_page_commits_atomically() {
    let db = Database::in_memory().unwrap();
    let query_hash = domain_hash("fixture:pages:v1:example.com");
    let names = BTreeSet::from(["api.example.com".to_owned()]);
    let page = PassivePaginationPage {
        position: 1,
        next_position: 2,
        records_seen: 1,
        expected_records: Some(1),
        expected_pages: Some(1),
        page_hash: domain_hash("api.example.com"),
        page_records: 1,
    };

    let novel = db
        .commit_passive_pagination_page_until(
            "example.com",
            "fixture",
            "pages",
            1,
            &query_hash,
            &page,
            &names,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();

    assert_eq!(novel, 1);
    let state = db
        .passive_pagination_resume_until(
            "example.com",
            "fixture",
            "pages",
            1,
            &query_hash,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
    assert_eq!(state.next_position, 2);
    assert_eq!(state.records_seen, 1);
    assert_eq!(
        db.observation_names("example.com", "passive:fixture")
            .unwrap(),
        vec!["api.example.com"]
    );
}

#[cfg(unix)]
fn unix_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
#[test]
fn unix_database_directory_file_and_sidecars_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("state");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
    let path = directory.join("fellaga.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    connection
        .execute("CREATE TABLE legacy_secret(value TEXT)", [])
        .unwrap();
    let wal = sqlite_companion_path(&path, "-wal");
    let shm = sqlite_companion_path(&path, "-shm");
    assert!(wal.exists());
    assert!(shm.exists());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&shm, std::fs::Permissions::from_mode(0o644)).unwrap();

    let database = Database::open(&path).unwrap();
    assert_eq!(unix_mode(&directory), 0o700);
    assert_eq!(unix_mode(&path), 0o600);
    assert!(
        wal.exists(),
        "le journal WAL doit être présent pendant l'ouverture"
    );
    assert!(
        shm.exists(),
        "le fichier SHM doit être présent pendant l'ouverture"
    );
    assert_eq!(unix_mode(&wal), 0o600);
    assert_eq!(unix_mode(&shm), 0o600);
    drop(database);
}

#[cfg(unix)]
#[test]
fn unix_shared_parent_is_not_repermissioned_but_database_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("unrelated.txt"), "keep").unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = root.path().join("fellaga.db");

    let database = Database::open(&path).unwrap();
    assert_eq!(unix_mode(root.path()), 0o755);
    assert_eq!(unix_mode(&path), 0o600);
    drop(database);
}

#[test]
fn v7_to_v9_preserves_5239_names_and_creates_a_consistent_pre_v8_backup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fellaga.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            r#"
                CREATE TABLE subdomains (
                    fqdn TEXT PRIMARY KEY,
                    root_domain TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    last_scan_id INTEGER,
                    times_seen INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1,
                    sources TEXT NOT NULL
                );
                WITH RECURSIVE counter(value) AS (
                    SELECT 1 UNION ALL SELECT value + 1 FROM counter WHERE value < 5239
                )
                INSERT INTO subdomains(
                    fqdn, root_domain, first_seen, last_seen, times_seen, active, sources
                )
                SELECT printf('host-%d.example.com', value), 'example.com', 1, 2, 1,
                       CASE WHEN value % 10 = 0 THEN 0 ELSE 1 END, 'legacy'
                FROM counter;
                PRAGMA user_version=7;
                "#,
        )
        .unwrap();
    drop(connection);

    let db = Database::open(&path).unwrap();
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM subdomains", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        5_239
    );
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT verification_state FROM subdomains WHERE fqdn='host-10.example.com'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "historical"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT verification_state FROM subdomains WHERE fqdn='host-1.example.com'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "unverified"
    );
    drop(connection);
    drop(db);

    let backup = std::fs::read_dir(directory.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("fellaga.db.pre-v8-"))
        })
        .expect("une sauvegarde pré-v8 doit exister");
    #[cfg(unix)]
    assert_eq!(unix_mode(&backup), 0o600);
    let backup_connection = Connection::open(backup).unwrap();
    assert_eq!(
        backup_connection
            .query_row("SELECT COUNT(*) FROM subdomains", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        5_239
    );
    assert_eq!(
        backup_connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        7
    );
}

#[test]
fn v8_to_v9_is_transactional_preserves_observations_and_creates_a_pre_v9_backup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fellaga.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            r#"
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    started_at INTEGER NOT NULL,
                    finished_at INTEGER,
                    status TEXT NOT NULL,
                    candidates INTEGER NOT NULL DEFAULT 0,
                    found INTEGER NOT NULL DEFAULT 0,
                    cache_hits INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    options_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL DEFAULT '[]',
                    learning_applied INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO scans(
                    id, domain, started_at, finished_at, status, options_json
                ) VALUES (41, 'example.com', 100, 200, 'complete', '{}');

                CREATE TABLE subdomains (
                    fqdn TEXT PRIMARY KEY,
                    root_domain TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    last_scan_id INTEGER REFERENCES scans(id),
                    times_seen INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1,
                    sources TEXT NOT NULL,
                    verification_state TEXT NOT NULL DEFAULT 'live',
                    last_verified_at INTEGER
                );
                INSERT INTO subdomains(
                    fqdn, root_domain, first_seen, last_seen, last_scan_id,
                    times_seen, active, sources, verification_state, last_verified_at
                ) VALUES (
                    'api.example.com', 'example.com', 101, 199, 41,
                    3, 1, 'passive:test,dns', 'live', 198
                );

                CREATE TABLE scan_findings (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    fqdn TEXT NOT NULL REFERENCES subdomains(fqdn) ON DELETE CASCADE,
                    wildcard INTEGER NOT NULL DEFAULT 0,
                    from_cache INTEGER NOT NULL DEFAULT 0,
                    confidence_score INTEGER NOT NULL DEFAULT 0,
                    confidence_label TEXT NOT NULL DEFAULT 'faible',
                    confidence_reasons_json TEXT NOT NULL DEFAULT '[]',
                    state TEXT NOT NULL DEFAULT 'unverified',
                    last_verified_at INTEGER,
                    evidence_families_json TEXT NOT NULL DEFAULT '[]',
                    authoritative_validation INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(scan_id, fqdn)
                );
                INSERT INTO scan_findings(
                    scan_id, fqdn, wildcard, from_cache, confidence_score,
                    confidence_label, confidence_reasons_json, state,
                    last_verified_at, evidence_families_json, authoritative_validation
                ) VALUES (
                    41, 'api.example.com', 0, 0, 93,
                    'forte', '["dns"]', 'live', 198, '["live_dns"]', 1
                );

                CREATE TABLE observed_names (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fqdn TEXT NOT NULL UNIQUE,
                    reversed_name TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                );
                CREATE TABLE observation_evidence (
                    root_domain TEXT NOT NULL,
                    name_id INTEGER NOT NULL REFERENCES observed_names(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    source TEXT NOT NULL,
                    value TEXT NOT NULL DEFAULT '',
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    times_seen INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY(root_domain, name_id, kind, source, value)
                );
                INSERT INTO observed_names(
                    id, fqdn, reversed_name, first_seen, last_seen
                ) VALUES (
                    7, 'api.example.com', 'com.example.api', 101, 199
                );
                INSERT INTO observation_evidence(
                    root_domain, name_id, kind, source, value,
                    first_seen, last_seen, times_seen
                ) VALUES (
                    'example.com', 7, 'passive', 'passive:test', 'fixture',
                    101, 199, 3
                );
                PRAGMA user_version=8;
                "#,
        )
        .unwrap();
    drop(connection);

    let database = Database::open(&path).unwrap();
    let connection = database.lock().unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        9
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT fqdn, reversed_name, first_seen, last_seen
                       FROM observed_names WHERE id=7"#,
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap(),
        (
            "api.example.com".to_owned(),
            "com.example.api".to_owned(),
            101,
            199
        )
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT kind, source, value, first_seen, last_seen, times_seen
                       FROM observation_evidence
                       WHERE root_domain='example.com' AND name_id=7"#,
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .unwrap(),
        (
            "passive".to_owned(),
            "passive:test".to_owned(),
            "fixture".to_owned(),
            101,
            199,
            3
        )
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT wildcard_verdict, owner_proofs_json,
                              generation_path_json, discovery_score
                       FROM scan_findings
                       WHERE scan_id=41 AND fqdn='api.example.com'"#,
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<f64>>(3)?,
                    ))
                },
            )
            .unwrap(),
        (
            "not_profiled".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
            None
        )
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT first_scan_id FROM subdomains WHERE fqdn='api.example.com'",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .unwrap(),
        None
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM sqlite_master
                       WHERE type='table' AND name IN (
                           'discovery_actions', 'intelligence_edges', 'name_templates',
                           'dnssec_proofs', 'ct_tiles', 'scheduler_arms'
                       )"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        6
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM pragma_table_info('ct_tiles')
                       WHERE name='checkpoint_hash' AND type='TEXT'"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM sqlite_master
                       WHERE type='table' AND name IN (
                           'passive_refresh_sessions', 'passive_refresh_seen',
                           'passive_refresh_leases'
                       )"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        3,
        "same-version additive repair must install replay-safe refresh state"
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM migration_state WHERE name='intelligence-v9'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    drop(connection);
    drop(database);

    let backup = std::fs::read_dir(directory.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("fellaga.db.pre-v9-"))
        })
        .expect("une sauvegarde pré-v9 doit exister");
    #[cfg(unix)]
    assert_eq!(unix_mode(&backup), 0o600);
    let backup_connection = Connection::open(backup).unwrap();
    assert_eq!(
        backup_connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        8
    );
    assert_eq!(
        backup_connection
            .query_row(
                "SELECT COUNT(*) FROM observation_evidence WHERE times_seen=3",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        backup_connection
            .query_row(
                r#"SELECT COUNT(*) FROM pragma_table_info('scan_findings')
                       WHERE name='wildcard_verdict'"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        backup_connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
}

#[test]
fn a_future_database_version_is_rejected_without_downgrading_it() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let connection = Connection::open(temporary.path()).unwrap();
    connection.pragma_update(None, "user_version", 10).unwrap();
    drop(connection);

    assert!(Database::open(temporary.path()).is_err());
    let connection = Connection::open(temporary.path()).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        10
    );
}

#[test]
fn version_six_database_is_normalized_once_without_losing_legacy_names() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let connection = Connection::open(temporary.path()).unwrap();
    connection
        .execute_batch(
            r#"
                CREATE TABLE passive_cache (
                    root_domain TEXT NOT NULL,
                    source TEXT NOT NULL,
                    names_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(root_domain, source)
                );
                INSERT INTO passive_cache(root_domain, source, names_json, updated_at)
                VALUES ('example.com', 'crtsh', '["api.example.com"]', 1);
                PRAGMA user_version=6;
                "#,
        )
        .unwrap();
    drop(connection);

    let db = Database::open(temporary.path()).unwrap();
    assert_eq!(
        db.observation_names("example.com", "passive:crtsh")
            .unwrap(),
        vec!["api.example.com"]
    );
    assert_eq!(
        db.passive_cache("example.com", "crtsh")
            .unwrap()
            .unwrap()
            .names,
        vec!["api.example.com"]
    );
    let connection = db.lock().unwrap();
    let (version, migrations): (i64, i64) = (
        connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row(
                "SELECT COUNT(*) FROM migration_state WHERE name='normalized-v7'",
                [],
                |row| row.get(0),
            )
            .unwrap(),
    );
    assert_eq!(version, 9);
    assert_eq!(migrations, 1);
}

#[test]
fn positive_cache_is_permanent_and_negative_cache_can_expire() {
    let db = Database::in_memory().unwrap();
    let hosts = vec!["www.example.com".to_owned(), "none.example.com".to_owned()];
    let answers = vec![ResolvedHost {
        fqdn: hosts[0].clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.1".to_owned(),
            ttl: 600,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: true,
        resolver_count: 3,
    }];
    db.update_cache(&hosts, &answers, 86_400, 300).unwrap();
    let positive_expiry = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT expires_at FROM dns_cache WHERE fqdn=?1",
            [&hosts[0]],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(positive_expiry, PERMANENT_EXPIRY);

    db.lock()
        .unwrap()
        .execute("UPDATE dns_cache SET expires_at=0", [])
        .unwrap();
    let cached = db.fresh_cache(&hosts).unwrap();
    assert!(matches!(cached[&hosts[0]], CachedAnswer::Positive(_)));
    let CachedAnswer::Positive(cached_positive) = &cached[&hosts[0]] else {
        unreachable!();
    };
    assert!(cached_positive.authoritative_validation);
    assert_eq!(cached_positive.resolver_count, 3);
    assert!(!cached.contains_key(&hosts[1]));
    assert_eq!(db.prune_cache().unwrap(), 1);

    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let finding = Finding {
        fqdn: hosts[0].clone(),
        records: answers[0].records.clone(),
        sources: BTreeSet::from(["test".to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(&BTreeSet::from(["test".to_owned()]), false, false),
        state: ObservationState::Live,
        last_verified_at: answers[0].last_verified_at,
        evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
        authoritative_validation: false,
        ..Finding::default()
    };
    let expected_confidence = finding.confidence.score;
    db.persist_findings(scan_id, "example.com", &[finding], 86_400)
        .unwrap();
    let record_expiry = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT expires_at FROM dns_records WHERE fqdn=?1",
            [&hosts[0]],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(record_expiry, PERMANENT_EXPIRY);
    let confidence = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT confidence_score FROM scan_findings WHERE scan_id=?1 AND fqdn=?2",
            params![scan_id, hosts[0]],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(confidence, i64::from(expected_confidence));
}

#[test]
fn corrupt_or_empty_positive_cache_entries_are_cache_misses() {
    let db = Database::in_memory().unwrap();
    let now = now_epoch();
    let connection = db.lock().unwrap();
    for (fqdn, records) in [
        ("broken.example.com", "not-json"),
        ("empty.example.com", "[]"),
    ] {
        connection
            .execute(
                r#"INSERT INTO dns_cache(
                       fqdn,status,records_json,expires_at,last_checked,resolver_count,authoritative
                       ) VALUES (?1,'positive',?2,?3,?4,1,0)"#,
                params![fqdn, records, PERMANENT_EXPIRY, now],
            )
            .unwrap();
    }
    drop(connection);
    let hosts = vec![
        "broken.example.com".to_owned(),
        "empty.example.com".to_owned(),
    ];
    assert!(db.fresh_cache(&hosts).unwrap().is_empty());
}

#[test]
fn indeterminate_dns_preserves_positive_cache_and_scan_provenance() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let host = "api.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: host.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.10".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let untouched = "untouched.example.com".to_owned();
    let make_finding = |fqdn: String| Finding {
        fqdn,
        records: answer.records.clone(),
        sources: BTreeSet::from(["refresh".to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(
            &BTreeSet::from(["refresh".to_owned()]),
            false,
            false,
        ),
        state: ObservationState::Live,
        last_verified_at: answer.last_verified_at,
        evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
        authoritative_validation: false,
        ..Finding::default()
    };
    db.persist_findings(
        scan_id,
        "example.com",
        &[make_finding(host.clone()), make_finding(untouched.clone())],
        86_400,
    )
    .unwrap();
    db.update_cache_outcomes(Some(scan_id), &[answer], &[], &[], 300)
        .unwrap();
    db.update_cache_outcomes(Some(scan_id), &[], &[], std::slice::from_ref(&host), 300)
        .unwrap();

    assert!(matches!(
        db.fresh_cache(std::slice::from_ref(&host)).unwrap()[&host],
        CachedAnswer::Positive(_)
    ));
    let states = db
        .inventory(Some("example.com"), false)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.fqdn, entry.state))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(states[&host], ObservationState::Live);
    assert_eq!(states[&untouched], ObservationState::Live);
    let connection = db.lock().unwrap();
    let rows = connection
        .prepare("SELECT scan_id, outcome FROM dns_verifications WHERE fqdn=?1 ORDER BY id")
        .unwrap()
        .query_map([&host], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![(scan_id, "live".to_owned()), (scan_id, "error".to_owned())]
    );
}

#[test]
fn unverified_findings_do_not_leave_active_dns_records() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let finding = Finding {
        fqdn: "wild.prod.example.com".to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        sources: BTreeSet::from(["passive:crtsh".to_owned()]),
        wildcard: true,
        from_cache: false,
        confidence: crate::confidence::assess(
            &BTreeSet::from(["passive:crtsh".to_owned()]),
            true,
            false,
        ),
        state: ObservationState::Unverified,
        last_verified_at: Some(now_epoch()),
        evidence_families: BTreeSet::from([crate::model::EvidenceFamily::CertificateTransparency]),
        authoritative_validation: false,
        ..Finding::default()
    };
    db.persist_findings(scan_id, "example.com", &[finding], 86_400)
        .unwrap();
    let connection = db.lock().unwrap();
    let subdomain_active: i64 = connection
        .query_row(
            "SELECT active FROM subdomains WHERE fqdn='wild.prod.example.com'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let record_active: i64 = connection
        .query_row(
            "SELECT active FROM dns_records WHERE fqdn='wild.prod.example.com'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((subdomain_active, record_active), (0, 0));
}

#[test]
fn wildcard_suspect_demotion_and_seed_requeue_are_atomic() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "api.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    db.persist_findings(
        scan_id,
        "example.com",
        &[Finding {
            fqdn: fqdn.clone(),
            records: answer.records.clone(),
            sources: BTreeSet::from(["dns:seed".to_owned()]),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            ..Finding::default()
        }],
        86_400,
    )
    .unwrap();
    db.update_cache_outcomes(Some(scan_id), &[answer], &[], &[], 300)
        .unwrap();
    let initial_sources = BTreeSet::from(["passive:first".to_owned()]);
    db.persist_scan_seed_candidates(scan_id, &[(fqdn.clone(), initial_sources, 10)], 10)
        .unwrap();
    let claimed = db.pending_scan_seed_candidates(scan_id, 1).unwrap();
    db.mark_scan_seed_candidates_started(scan_id, std::slice::from_ref(&fqdn))
        .unwrap();
    db.mark_scan_seed_candidates_done(scan_id, std::slice::from_ref(&fqdn))
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 0);

    db.demote_and_requeue_scan_findings(
        scan_id,
        &[(
            fqdn.clone(),
            BTreeSet::from(["dns:resume-wildcard".to_owned()]),
            50,
        )],
        "test revalidation",
    )
    .unwrap();

    let inventory = db.inventory(Some("example.com"), false).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].state, ObservationState::Unverified);
    assert!(matches!(
        db.fresh_cache(std::slice::from_ref(&fqdn)).unwrap()[&fqdn],
        CachedAnswer::Positive(_)
    ));
    let queued = db.pending_scan_seed_candidates(scan_id, 1).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].0, fqdn);
    assert!(queued[0].1.contains("passive:first"));
    assert!(queued[0].1.contains("dns:resume-wildcard"));
    assert_eq!(queued[0].2, 50);
    let connection = db.lock().unwrap();
    let (finding_state, verdict, active_record, latest_outcome): (String, String, i64, String) =
        connection
            .query_row(
                r#"SELECT finding.state, finding.wildcard_verdict, record.active,
                          verification.outcome
                   FROM scan_findings AS finding
                   JOIN dns_records AS record ON record.fqdn=finding.fqdn
                   JOIN dns_verifications AS verification ON verification.id=(
                       SELECT MAX(id) FROM dns_verifications WHERE fqdn=finding.fqdn
                   )
                   WHERE finding.scan_id=?1 AND finding.fqdn=?2"#,
                params![scan_id, fqdn],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
    assert_eq!(finding_state, "unverified");
    assert_eq!(verdict, "ambiguous");
    assert_eq!(active_record, 0);
    assert_eq!(latest_outcome, "unverified");
}

#[test]
fn provider_only_merge_preserves_verified_inventory_and_dns_record_state() {
    let db = Database::in_memory().unwrap();
    let live = "live.example.com";
    let historical = "historical.example.com";
    let new = "new.example.com";
    let first_scan = db.create_scan("example.com", &json!({})).unwrap();
    let verified = |fqdn: &str, address: &str, checked_at: i64| Finding {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: address.to_owned(),
            ttl: 60,
        }],
        sources: BTreeSet::from(["dns".to_owned()]),
        state: ObservationState::Live,
        last_verified_at: Some(checked_at),
        evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
        ..Finding::default()
    };
    db.persist_findings(
        first_scan,
        "example.com",
        &[
            verified(live, "192.0.2.10", 101),
            verified(historical, "192.0.2.11", 102),
        ],
        60,
    )
    .unwrap();
    db.mark_inactive(&[historical.to_owned()]).unwrap();

    let second_scan = db.create_scan("example.com", &json!({})).unwrap();
    let provider_only = |fqdn: &str| Finding {
        fqdn: fqdn.to_owned(),
        sources: BTreeSet::from(["passive:crtsh:cache".to_owned()]),
        state: ObservationState::Unverified,
        ..Finding::default()
    };
    db.persist_unverified_findings_preserving_state(
        second_scan,
        "example.com",
        &[
            provider_only(live),
            provider_only(historical),
            provider_only(new),
        ],
    )
    .unwrap();

    let inventory = db
        .inventory(Some("example.com"), false)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.fqdn.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(inventory[live].state, ObservationState::Live);
    assert_eq!(inventory[live].last_verified_at, Some(101));
    assert_eq!(inventory[historical].state, ObservationState::Historical);
    assert_eq!(inventory[historical].last_verified_at, Some(102));
    assert_eq!(inventory[new].state, ObservationState::Unverified);
    assert_eq!(inventory[new].last_verified_at, None);
    for fqdn in [live, historical] {
        assert!(inventory[fqdn].sources.contains("dns"));
        assert!(inventory[fqdn].sources.contains("passive:crtsh:cache"));
    }

    let connection = db.lock().unwrap();
    let active = |fqdn: &str| -> i64 {
        connection
            .query_row(
                "SELECT active FROM dns_records WHERE fqdn=?1",
                [fqdn],
                |row| row.get(0),
            )
            .unwrap()
    };
    assert_eq!(active(live), 1);
    assert_eq!(active(historical), 0);
    let new_record_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM dns_records WHERE fqdn=?1",
            [new],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(new_record_count, 0);
}

#[test]
fn later_wildcard_findings_union_sources_and_clear_invalidated_live_verification_time() {
    let db = Database::in_memory().unwrap();
    let first_scan = db.create_scan("example.com", &json!({})).unwrap();
    let mut finding = Finding {
        fqdn: "api.example.com".to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.10".to_owned(),
            ttl: 60,
        }],
        sources: BTreeSet::from(["passive:first".to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(
            &BTreeSet::from(["passive:first".to_owned()]),
            false,
            false,
        ),
        state: ObservationState::Live,
        last_verified_at: Some(100),
        evidence_families: BTreeSet::from([crate::model::EvidenceFamily::PassiveDns]),
        authoritative_validation: false,
        ..Finding::default()
    };
    db.persist_findings(first_scan, "example.com", &[finding.clone()], 60)
        .unwrap();
    db.persist_findings(first_scan, "example.com", &[finding.clone()], 60)
        .unwrap();

    let second_scan = db.create_scan("example.com", &json!({})).unwrap();
    finding.sources = BTreeSet::from(["web:second".to_owned()]);
    finding.wildcard = true;
    finding.state = ObservationState::Unverified;
    finding.last_verified_at = Some(200);
    db.persist_findings(second_scan, "example.com", &[finding], 60)
        .unwrap();

    let connection = db.lock().unwrap();
    let (sources, last_verified_at, times_seen): (String, Option<i64>, i64) = connection
            .query_row(
                "SELECT sources,last_verified_at,times_seen FROM subdomains WHERE fqdn='api.example.com'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
    assert_eq!(sources, "passive:first,web:second");
    assert_eq!(last_verified_at, None);
    assert_eq!(times_seen, 2, "one scan must increment inventory only once");
}

#[test]
fn candidate_indexes_cover_priority_relative_name_and_budget_counts() {
    let db = Database::in_memory().unwrap();
    let connection = db.lock().unwrap();
    let count: i64 = connection
        .query_row(
            r#"SELECT COUNT(*) FROM sqlite_master
                    WHERE type='index' AND name IN (
                       'idx_scan_candidates_relative', 'idx_candidate_priors_priority',
                       'idx_scan_candidates_unrecorded'
                    )"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn candidate_outcome_queries_force_the_fqdn_verification_index() {
    let db = Database::in_memory().unwrap();
    let connection = db.lock().unwrap();
    let plans = [
        r#"EXPLAIN QUERY PLAN
               UPDATE scan_seed_candidates SET status=CASE
                   WHEN COALESCE((
                     SELECT verification.outcome
                     FROM dns_verifications AS verification
                          INDEXED BY idx_dns_verifications_name
                     WHERE verification.scan_id=1
                       AND verification.fqdn=scan_seed_candidates.fqdn
                     ORDER BY verification.checked_at DESC, verification.id DESC
                     LIMIT 1
                   ), '')='error' AND attempts<3 THEN 'queued'
                   ELSE 'done'
               END
               WHERE scan_id=1 AND fqdn IN ('plan.example.com')"#,
        r#"EXPLAIN QUERY PLAN
               UPDATE scan_candidates SET status=CASE
                   WHEN COALESCE((
                     SELECT verification.outcome
                     FROM dns_verifications AS verification
                          INDEXED BY idx_dns_verifications_name
                     WHERE verification.scan_id=1
                       AND verification.fqdn=scan_candidates.fqdn
                     ORDER BY verification.checked_at DESC, verification.id DESC
                     LIMIT 1
                   ), '')='error' AND attempts<3 THEN 'queued'
                   ELSE 'done'
               END
               WHERE scan_id=1 AND fqdn IN ('plan.example.com')"#,
        r#"EXPLAIN QUERY PLAN
               UPDATE scan_candidates SET learning_recorded=1
               WHERE scan_id=1 AND fqdn='plan.example.com' AND learning_recorded=0
                 AND (
                   attempts>=3
                   OR COALESCE((
                     SELECT verification.outcome
                     FROM dns_verifications AS verification
                          INDEXED BY idx_dns_verifications_name
                     WHERE verification.scan_id=1
                       AND verification.fqdn=scan_candidates.fqdn
                     ORDER BY verification.checked_at DESC, verification.id DESC
                     LIMIT 1
                   ), '')<>'error'
                 )"#,
    ];
    for sql in plans {
        let mut statement = connection.prepare(sql).unwrap();
        let details = statement
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("idx_dns_verifications_name (fqdn=?)")),
            "expected fqdn index in query plan: {details:?}"
        );
        assert!(
            details
                .iter()
                .all(|detail| !detail.contains("idx_dns_verifications_scan (scan_id=?)")),
            "scan-wide verification lookup leaked into query plan: {details:?}"
        );
    }
}

#[test]
fn dns_validation_journal_is_append_only() {
    let db = Database::in_memory().unwrap();
    let host = "api.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: host.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.10".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: true,
        resolver_count: 3,
    };
    db.update_cache(std::slice::from_ref(&host), &[answer], 60, 30)
        .unwrap();
    let connection = db.lock().unwrap();
    let id: i64 = connection
        .query_row("SELECT id FROM dns_verifications LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(
        connection
            .execute(
                "UPDATE dns_verifications SET outcome='negative' WHERE id=?1",
                [id]
            )
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM dns_verifications WHERE id=?1", [id])
            .is_err()
    );
}

#[test]
fn discovery_fast_path_excludes_all_durable_known_name_sources() {
    let db = Database::in_memory().unwrap();
    let inventory = "inventory.example.com".to_owned();
    let observed = "observed.example.com".to_owned();
    let cached = "cached.example.com".to_owned();
    let negative = "negative.example.com".to_owned();
    let unknown = "unknown.example.com".to_owned();

    db.lock()
        .unwrap()
        .execute(
            r#"INSERT INTO subdomains(
                       fqdn, root_domain, first_seen, last_seen, times_seen,
                       active, sources, verification_state
                   ) VALUES (?1, 'example.com', 1, 1, 1, 0, 'test', 'historical')"#,
            [&inventory],
        )
        .unwrap();
    db.store_observations(
        "example.com",
        vec![ObservationInput {
            fqdn: observed.clone(),
            kind: "passive".to_owned(),
            source: "passive:test".to_owned(),
            value: String::new(),
        }],
    )
    .unwrap();
    let answer = ResolvedHost {
        fqdn: cached.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.50".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    db.update_cache_outcomes(None, &[answer], std::slice::from_ref(&negative), &[], 30)
        .unwrap();

    let known = db
        .known_discovery_names(&[
            inventory.clone(),
            observed.clone(),
            cached.clone(),
            negative,
            unknown,
        ])
        .unwrap();
    assert_eq!(known, BTreeSet::from([cached, inventory, observed]));
}

#[test]
fn discovery_negatives_only_append_journal_and_finalize_candidates() {
    let db = Database::in_memory().unwrap();
    let previous_scan = db.create_scan("example.com", &json!({})).unwrap();
    let live_host = "api.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: live_host.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.10".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: true,
        resolver_count: 3,
    };
    let sources = BTreeSet::from(["dns:trusted".to_owned()]);
    let finding = Finding {
        fqdn: live_host.clone(),
        records: answer.records.clone(),
        sources: sources.clone(),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(&sources, false, true),
        state: ObservationState::Live,
        last_verified_at: answer.last_verified_at,
        evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
        authoritative_validation: true,
        ..Finding::default()
    };
    db.persist_findings(previous_scan, "example.com", &[finding], 86_400)
        .unwrap();
    db.update_cache_outcomes(
        Some(previous_scan),
        std::slice::from_ref(&answer),
        &[],
        &[],
        300,
    )
    .unwrap();

    let (inventory_before, record_before, cache_before) = {
        let connection = db.lock().unwrap();
        let inventory = connection
            .query_row(
                r#"SELECT active, verification_state, last_verified_at
                       FROM subdomains WHERE fqdn=?1"#,
                [&live_host],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .unwrap();
        let record = connection
            .query_row(
                r#"SELECT record_type, value, ttl, expires_at, active
                       FROM dns_records WHERE fqdn=?1"#,
                [&live_host],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .unwrap();
        let cache = connection
            .query_row(
                r#"SELECT status, records_json, expires_at, last_checked,
                              resolver_count, authoritative
                       FROM dns_cache WHERE fqdn=?1"#,
                [&live_host],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .unwrap();
        (inventory, record, cache)
    };

    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let mut candidates = vec![("api".to_owned(), "test".to_owned(), 1)];
    candidates.extend((0..501).map(|index| (format!("absent-{index}"), "test".to_owned(), 1)));
    db.persist_scan_candidates(scan_id, "example.com", &candidates)
        .unwrap();
    assert_eq!(
        db.pending_scan_candidates(scan_id, 1_000).unwrap().len(),
        502
    );

    let mut hosts = candidates
        .iter()
        .map(|(relative_name, _, _)| format!("{relative_name}.example.com"))
        .collect::<Vec<_>>();
    hosts.push(live_host.clone());
    hosts.push("absent-0.example.com".to_owned());
    db.record_discovery_negatives(scan_id, &hosts).unwrap();
    hosts.truncate(502);
    db.mark_scan_candidates_done(scan_id, &hosts).unwrap();

    assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 0);
    let connection = db.lock().unwrap();
    let terminal: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1 AND status='done'",
            [scan_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(terminal, 502);

    let journal: (i64, i64, i64, i64) = connection
        .query_row(
            r#"SELECT COUNT(*), COUNT(DISTINCT fqdn),
                          COUNT(DISTINCT details_json),
                          SUM(outcome='negative' AND resolver_count=1
                              AND authoritative=0 AND records_hash IS NULL)
                   FROM dns_verifications WHERE scan_id=?1"#,
            [scan_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(journal, (502, 502, 1, 502));
    let details: Value = serde_json::from_str(
        &connection
            .query_row(
                "SELECT details_json FROM dns_verifications WHERE scan_id=?1 LIMIT 1",
                [scan_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        details,
        json!({
            "scope": "discovery-only",
            "cache_write": false,
            "inventory_write": false
        })
    );

    let inventory_after = connection
        .query_row(
            r#"SELECT active, verification_state, last_verified_at
                   FROM subdomains WHERE fqdn=?1"#,
            [&live_host],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .unwrap();
    let record_after = connection
        .query_row(
            r#"SELECT record_type, value, ttl, expires_at, active
                   FROM dns_records WHERE fqdn=?1"#,
            [&live_host],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .unwrap();
    let cache_after = connection
        .query_row(
            r#"SELECT status, records_json, expires_at, last_checked,
                          resolver_count, authoritative
                   FROM dns_cache WHERE fqdn=?1"#,
            [&live_host],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(inventory_after, inventory_before);
    assert_eq!(inventory_after.0, 1);
    assert_eq!(inventory_after.1, "live");
    assert_eq!(record_after, record_before);
    assert_eq!(record_after.4, 1);
    assert_eq!(cache_after, cache_before);
    assert_eq!(cache_after.0, "positive");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM subdomains WHERE fqdn LIKE 'absent-%'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM dns_records WHERE fqdn LIKE 'absent-%'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM dns_cache WHERE fqdn LIKE 'absent-%'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn negative_demotions_are_chunked_without_creating_absent_inventory() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let existing = ["first.example.com", "last.example.com"];
    let now = now_epoch();
    {
        let connection = db.lock().unwrap();
        for (offset, host) in existing.iter().enumerate() {
            connection
                .execute(
                    r#"INSERT INTO subdomains(
                               fqdn, root_domain, first_seen, last_seen, last_scan_id,
                               times_seen, active, sources, verification_state, last_verified_at
                           ) VALUES (?1, 'example.com', ?2, ?2, ?3, 1, 1, 'dns:test', 'live', ?2)"#,
                    params![host, now, scan_id],
                )
                .unwrap();
            connection
                .execute(
                    r#"INSERT INTO dns_records(
                               fqdn, record_type, value, ttl, expires_at,
                               first_seen, last_seen, active
                           ) VALUES (?1, 'A', ?2, 60, ?3, ?4, ?4, 1)"#,
                    params![
                        host,
                        format!("192.0.2.{}", offset + 10),
                        PERMANENT_EXPIRY,
                        now
                    ],
                )
                .unwrap();
        }
    }

    let mut negatives = Vec::with_capacity(502);
    negatives.push(existing[0].to_owned());
    negatives.extend((0..500).map(|index| format!("absent-{index}.example.com")));
    negatives.push(existing[1].to_owned());
    db.update_cache_outcomes(Some(scan_id), &[], &negatives, &[], 300)
        .unwrap();

    let connection = db.lock().unwrap();
    let scalar = |sql: &str| {
        connection
            .query_row(sql, [], |row| row.get::<_, i64>(0))
            .unwrap()
    };
    assert_eq!(scalar("SELECT COUNT(*) FROM subdomains"), 2);
    assert_eq!(
        scalar(
            "SELECT COUNT(*) FROM subdomains \
                 WHERE active=0 AND verification_state='historical'"
        ),
        2
    );
    assert_eq!(
        scalar("SELECT COUNT(*) FROM subdomains WHERE fqdn LIKE 'absent-%'"),
        0
    );
    assert_eq!(scalar("SELECT COUNT(*) FROM dns_records WHERE active=0"), 2);
    assert_eq!(scalar("SELECT COUNT(*) FROM dns_cache"), 502);
    assert_eq!(
        scalar("SELECT COUNT(*) FROM dns_verifications WHERE scan_id IS NOT NULL"),
        502
    );
}

#[test]
fn scan_candidates_are_loaded_in_bounded_persistent_batches() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.persist_scan_candidates(
        scan_id,
        "example.com",
        &[("priority".to_owned(), "mutation".to_owned(), 10)],
    )
    .unwrap();
    db.persist_prior_candidates_to_scan(scan_id, "example.com", 5)
        .unwrap();
    let first = db.pending_scan_candidates(scan_id, 1).unwrap();
    assert_eq!(first[0].0, "priority");
    db.mark_scan_candidates_done(scan_id, &[format!("{}.example.com", first[0].0)])
        .unwrap();
    assert_eq!(
        db.pending_scan_candidate_count(scan_id).unwrap(),
        db.scan_candidate_count(scan_id).unwrap() - 1
    );
    db.clear_scan_candidates(scan_id).unwrap();
    assert_eq!(db.scan_candidate_count(scan_id).unwrap(), 0);
}

#[test]
fn exhausted_active_budget_leaves_every_active_source_queued() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.persist_scan_candidates(
        scan_id,
        "example.com",
        &[
            ("generated".to_owned(), "builtin".to_owned(), 100),
            ("resumed".to_owned(), "mutation".to_owned(), 90),
            ("explicit".to_owned(), "wordlist".to_owned(), 1),
        ],
    )
    .unwrap();

    let eligible = db
        .pending_scan_candidates_eligible(scan_id, 10, false)
        .unwrap();
    assert!(eligible.is_empty());
    assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 3);
    assert_eq!(
        db.pending_scan_candidate_count_eligible(scan_id, false)
            .unwrap(),
        0
    );
    let untouched_active: i64 = db
        .lock()
        .unwrap()
        .query_row(
            r#"SELECT COUNT(*) FROM scan_candidates
                   WHERE scan_id=?1 AND status='queued' AND attempts=0"#,
            [scan_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(untouched_active, 3);

    let resumed = db
        .pending_scan_candidates_eligible(scan_id, 10, true)
        .unwrap();
    assert_eq!(
        resumed.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        vec!["generated", "resumed", "explicit"]
    );
}

#[test]
fn unstarted_deadline_candidate_requeues_without_consuming_an_attempt() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "never-sent.example.com".to_owned();
    db.persist_scan_candidates(
        scan_id,
        "example.com",
        &[("never-sent".to_owned(), "builtin".to_owned(), 1)],
    )
    .unwrap();
    assert_eq!(db.pending_scan_candidates(scan_id, 1).unwrap().len(), 1);
    db.requeue_unstarted_scan_candidates(scan_id, std::slice::from_ref(&fqdn))
        .unwrap();
    let (status, attempts): (String, i64) = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status,attempts FROM scan_candidates WHERE scan_id=?1 AND fqdn=?2",
            params![scan_id, fqdn],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((status.as_str(), attempts), ("queued", 0));
}

#[test]
fn recursive_queue_pages_and_parent_cursors_survive_resume() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "options")
        .unwrap();
    let words = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
    assert_eq!(
        db.ensure_scan_recursive_words(scan_id, &words).unwrap(),
        words
    );
    assert_eq!(
        db.ensure_scan_recursive_words(scan_id, &["changed".to_owned()])
            .unwrap(),
        words,
        "a resume must retain the original ordinal word list"
    );
    db.persist_scan_recursive_parents(scan_id, 2, &["api.example.com".to_owned()])
        .unwrap();
    assert_eq!(
        db.refill_scan_recursive_candidates(scan_id, 2, 2).unwrap(),
        2
    );
    let first = db.pending_scan_recursive_candidates(scan_id, 2, 2).unwrap();
    assert_eq!(
        first.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        vec!["a.api.example.com", "b.api.example.com"]
    );
    db.complete_scan_recursive_candidates(scan_id, &[first[0].0.clone()])
        .unwrap();
    db.requeue_unstarted_scan_recursive_candidates(scan_id, &[first[1].0.clone()])
        .unwrap();
    assert_eq!(
        db.refill_scan_recursive_candidates(scan_id, 2, 2).unwrap(),
        2
    );
    let second = db.pending_scan_recursive_candidates(scan_id, 2, 2).unwrap();
    assert_eq!(
        second.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        vec!["b.api.example.com", "c.api.example.com"]
    );

    db.pause_scan(scan_id, 0, 0, 0, 1, &[]).unwrap();
    db.reopen_scan(scan_id).unwrap();
    let resumed = db.pending_scan_recursive_candidates(scan_id, 2, 2).unwrap();
    assert_eq!(
        resumed.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        vec!["b.api.example.com", "c.api.example.com"]
    );
    db.complete_scan_recursive_candidates(
        scan_id,
        &resumed.into_iter().map(|row| row.0).collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!db.scan_recursive_depth_has_more(scan_id, 2).unwrap());
    assert!(!db.scan_recursive_has_more(scan_id).unwrap());
}

#[test]
fn live_results_from_the_same_scan_can_be_rehydrated_for_recursive_parents() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let answer = ResolvedHost {
        fqdn: "api.example.com".to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(123),
        authoritative_validation: true,
        resolver_count: 2,
    };
    db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 300)
        .unwrap();
    let sources = BTreeSet::from(["dns:test".to_owned()]);
    db.persist_findings(
        scan_id,
        "example.com",
        &[Finding {
            fqdn: answer.fqdn.clone(),
            records: answer.records.clone(),
            sources: sources.clone(),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(&sources, false, false),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            authoritative_validation: true,
            ..Finding::default()
        }],
        86_400,
    )
    .unwrap();

    let hydrated = db.live_scan_answers(scan_id).unwrap();
    assert_eq!(hydrated.len(), 1);
    assert_eq!(hydrated[0].0.fqdn, answer.fqdn);
    assert_eq!(hydrated[0].0.records, answer.records);
    assert!(hydrated[0].0.from_cache);
    assert!(hydrated[0].0.authoritative_validation);
    assert_eq!(hydrated[0].1, sources);
}

#[test]
fn passive_seed_queue_is_prioritized_durable_and_resumable() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "options")
        .unwrap();
    let axfr_sources = BTreeSet::from(["axfr:ns1.example.com".to_owned()]);
    let multi_sources = BTreeSet::from(["passive:crtsh".to_owned(), "passive:wayback".to_owned()]);
    let stale_sources = BTreeSet::from(["passive:otx:stale".to_owned()]);
    db.persist_scan_seed_candidates(
        scan_id,
        &[
            ("old.example.com".to_owned(), stale_sources.clone(), 10),
            ("api.example.com".to_owned(), multi_sources.clone(), 20),
            ("zone.example.com".to_owned(), axfr_sources.clone(), 30),
        ],
        3,
    )
    .unwrap();

    let first = db.pending_scan_seed_candidates(scan_id, 2).unwrap();
    assert_eq!(
        first.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        vec!["zone.example.com", "api.example.com"]
    );
    assert_eq!(first[0].1, axfr_sources);
    assert_eq!(first[1].1, multi_sources);
    db.mark_scan_seed_candidates_started(scan_id, &[first[0].0.clone()])
        .unwrap();
    db.mark_scan_seed_candidates_done(scan_id, &[first[0].0.clone()])
        .unwrap();

    db.lock()
        .unwrap()
        .execute(
            "UPDATE scans SET status='interrupted' WHERE id=?1",
            [scan_id],
        )
        .unwrap();
    db.reopen_scan(scan_id).unwrap();
    let resumed = db.pending_scan_seed_candidates(scan_id, 10).unwrap();
    assert_eq!(
        resumed.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        vec!["api.example.com", "old.example.com"]
    );
    assert_eq!(resumed[1].1, stale_sources);
    assert_eq!(db.scan_seed_candidate_count(scan_id).unwrap(), 3);

    db.clear_scan_candidates(scan_id).unwrap();
    assert_eq!(db.scan_seed_candidate_count(scan_id).unwrap(), 0);
}

#[test]
fn named_seed_claim_is_atomic_exact_and_bounded() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let sources = BTreeSet::from(["passive:ct-direct".to_owned()]);
    db.persist_scan_seed_candidates(
        scan_id,
        &[
            ("a.example.com".to_owned(), sources.clone(), 1),
            ("b.example.com".to_owned(), sources.clone(), 2),
            ("c.example.com".to_owned(), sources, 3),
        ],
        3,
    )
    .unwrap();
    assert_eq!(
        db.pending_scan_seed_candidates(scan_id, 1).unwrap()[0].0,
        "c.example.com"
    );

    let claimed = db
        .claim_scan_seed_candidates_by_name(
            scan_id,
            &[
                "c.example.com".to_owned(),
                "b.example.com".to_owned(),
                "missing.example.com".to_owned(),
                "b.example.com".to_owned(),
            ],
        )
        .unwrap();
    assert_eq!(claimed, vec!["b.example.com"]);
    assert!(
        db.claim_scan_seed_candidates_by_name(scan_id, &["b.example.com".to_owned()],)
            .unwrap()
            .is_empty()
    );
    let connection = db.lock().unwrap();
    let mut statement = connection
            .prepare(
                "SELECT fqdn, status, attempts FROM scan_seed_candidates WHERE scan_id=?1 ORDER BY fqdn",
            )
            .unwrap();
    let states = statement
        .query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    drop(statement);
    drop(connection);
    assert_eq!(
        states,
        vec![
            ("a.example.com".to_owned(), "queued".to_owned(), 0),
            ("b.example.com".to_owned(), "processing".to_owned(), 0),
            ("c.example.com".to_owned(), "processing".to_owned(), 0),
        ]
    );

    let too_many = (0..=MAX_NAMED_SEED_CLAIM)
        .map(|index| format!("host-{index}.example.com"))
        .collect::<Vec<_>>();
    assert!(
        db.claim_scan_seed_candidates_by_name(scan_id, &too_many)
            .is_err()
    );
    assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 1);
}

#[test]
fn passive_seed_errors_retry_three_times_then_remain_terminal_on_resume() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "options")
        .unwrap();
    let host = "api.example.com".to_owned();
    db.persist_scan_seed_candidates(
        scan_id,
        &[(
            host.clone(),
            BTreeSet::from(["passive:test".to_owned()]),
            10,
        )],
        1,
    )
    .unwrap();

    for attempt in 1..=3 {
        assert_eq!(
            db.pending_scan_seed_candidates(scan_id, 1).unwrap()[0].0,
            host
        );
        db.mark_scan_seed_candidates_started(scan_id, std::slice::from_ref(&host))
            .unwrap();
        db.update_cache_outcomes(Some(scan_id), &[], &[], std::slice::from_ref(&host), 300)
            .unwrap();
        db.mark_scan_seed_candidates_done(scan_id, std::slice::from_ref(&host))
            .unwrap();
        assert_eq!(
            db.pending_scan_seed_candidate_count(scan_id).unwrap(),
            i64::from(attempt < 3)
        );
    }

    db.finish_scan(scan_id, "interrupted", 1, 0, 0, 1, &[])
        .unwrap();
    db.reopen_scan(scan_id).unwrap();
    assert!(
        db.pending_scan_seed_candidates(scan_id, 1)
            .unwrap()
            .is_empty()
    );
    let (status, attempts): (String, i64) = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status,attempts FROM scan_seed_candidates WHERE scan_id=?1 AND fqdn=?2",
            params![scan_id, host],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((status.as_str(), attempts), ("done", 3));
}

#[test]
fn promoting_a_terminal_active_candidate_to_a_seed_does_not_reopen_word_budget() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let host = "api.example.com".to_owned();
    db.persist_scan_candidates(
        scan_id,
        "example.com",
        &[("api".to_owned(), "mutation".to_owned(), 10)],
    )
    .unwrap();
    db.pending_scan_candidates(scan_id, 1).unwrap();
    db.update_cache_outcomes(Some(scan_id), &[], std::slice::from_ref(&host), &[], 300)
        .unwrap();
    db.record_scan_candidate_results(
        scan_id,
        &[(host.clone(), "api".to_owned(), "mutation".to_owned(), false)],
    )
    .unwrap();
    db.mark_scan_candidates_done(scan_id, std::slice::from_ref(&host))
        .unwrap();
    assert_eq!(db.scan_candidate_budget_count(scan_id).unwrap(), 1);

    db.persist_scan_seed_candidates(
        scan_id,
        &[(host, BTreeSet::from(["passive:test".to_owned()]), 20)],
        1,
    )
    .unwrap();
    assert_eq!(db.scan_candidate_count(scan_id).unwrap(), 0);
    assert_eq!(db.scan_candidate_budget_count(scan_id).unwrap(), 1);
}

#[test]
fn a_full_seed_queue_merges_provenance_and_replaces_only_unattempted_low_priority_rows() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let original = BTreeSet::from(["passive:first".to_owned()]);
    db.persist_scan_seed_candidates(
        scan_id,
        &[
            ("attempted.example.com".to_owned(), original.clone(), 10),
            ("low.example.com".to_owned(), original.clone(), 5),
        ],
        2,
    )
    .unwrap();
    assert_eq!(
        db.pending_scan_seed_candidates(scan_id, 1).unwrap()[0].0,
        "attempted.example.com"
    );
    db.persist_scan_seed_candidates(
        scan_id,
        &[
            (
                "attempted.example.com".to_owned(),
                BTreeSet::from(["passive:second".to_owned()]),
                30,
            ),
            (
                "high.example.com".to_owned(),
                BTreeSet::from(["axfr:ns1.example.com".to_owned()]),
                20,
            ),
        ],
        2,
    )
    .unwrap();

    let rows = db.scan_seed_candidates_for_output(scan_id).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|(fqdn, sources)| {
        fqdn == "attempted.example.com"
            && sources == &BTreeSet::from(["passive:first".to_owned(), "passive:second".to_owned()])
    }));
    assert!(rows.iter().any(|(fqdn, _)| fqdn == "high.example.com"));
    assert!(!rows.iter().any(|(fqdn, _)| fqdn == "low.example.com"));
}

#[test]
fn scan_finalization_applies_learning_exactly_once() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "options")
        .unwrap();
    let attempts = HashMap::from([("mutation".to_owned(), 2_usize)]);
    let successes = HashMap::from([("mutation".to_owned(), 1_usize)]);
    let attempted_words = BTreeSet::from(["api".to_owned(), "dev".to_owned()]);
    let successful_words = BTreeSet::from(["api".to_owned()]);
    let successful_patterns = BTreeSet::from(["api".to_owned()]);

    db.finalize_scan_with_learning(
        scan_id,
        "example.com",
        &attempts,
        &successes,
        &attempted_words,
        &successful_words,
        &successful_patterns,
        2,
        1,
        0,
        10,
        &[],
    )
    .unwrap();
    assert!(
        db.finalize_scan_with_learning(
            scan_id,
            "example.com",
            &attempts,
            &successes,
            &attempted_words,
            &successful_words,
            &successful_patterns,
            2,
            1,
            0,
            10,
            &[],
        )
        .is_err()
    );

    let connection = db.lock().unwrap();
    let scan: (String, i64) = connection
        .query_row(
            "SELECT status,learning_applied FROM scans WHERE id=?1",
            [scan_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(scan, ("completed".to_owned(), 1));
    let word: (i64, i64, i64) = connection
        .query_row(
            "SELECT attempts,successes,unique_domains FROM word_stats WHERE word='api'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(word, (1, 1, 1));
    let generator: (i64, i64) = connection
        .query_row(
            "SELECT attempts,successes FROM generator_stats WHERE generator='mutation'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(generator, (2, 1));
}

#[test]
fn builtin_corpus_feed_resumes_from_its_durable_cursor() {
    let db = Database::in_memory().unwrap();
    let expected = db.prior_candidates(4).unwrap();
    assert_eq!(expected.len(), 4);
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();

    assert_eq!(
        db.refill_prior_candidates_to_scan(scan_id, "example.com", 2)
            .unwrap()
            .0,
        2
    );
    let first = db.pending_scan_candidates(scan_id, 2).unwrap();
    assert_eq!(
        first.iter().map(|row| row.0.clone()).collect::<Vec<_>>(),
        expected[..2]
    );
    db.mark_scan_candidates_done(
        scan_id,
        &first
            .iter()
            .map(|row| format!("{}.example.com", row.0))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    assert_eq!(
        db.refill_prior_candidates_to_scan(scan_id, "example.com", 2)
            .unwrap()
            .0,
        2
    );
    let second = db.pending_scan_candidates(scan_id, 2).unwrap();
    assert_eq!(
        second.iter().map(|row| row.0.clone()).collect::<Vec<_>>(),
        expected[2..]
    );
    let cursor: i64 = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT cursor FROM scan_candidate_feeds WHERE scan_id=?1 AND source='builtin'",
            [scan_id],
            |row| row.get(0),
        )
        .unwrap();
    let expected_cursor: i64 = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT priority FROM candidate_priors WHERE relative_name=?1",
            [&expected[3]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(cursor, expected_cursor);
    let cursor_text: String = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT cursor_text FROM scan_candidate_feeds WHERE scan_id=?1 AND source='builtin'",
            [scan_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(cursor_text, expected[3]);
}

#[test]
fn stale_running_scans_are_reconciled_but_fresh_leases_are_preserved() {
    let db = Database::in_memory().unwrap();
    let stale = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(stale, "example.com", "running", "stale-hash")
        .unwrap();
    let fresh = db.create_scan("example.net", &json!({})).unwrap();
    db.upsert_checkpoint(fresh, "example.net", "running", "fresh-hash")
        .unwrap();
    db.stage_refresh_wildcard_candidates(stale, &["old.example.com".to_owned()])
        .unwrap();
    db.stage_refresh_wildcard_candidates(fresh, &["new.example.net".to_owned()])
        .unwrap();
    db.lock()
        .unwrap()
        .execute(
            "UPDATE scan_checkpoints SET updated_at=?1 WHERE scan_id=?2",
            params![now_epoch() - 600, stale],
        )
        .unwrap();

    assert_eq!(
        db.reconcile_stale_scans(std::time::Duration::from_secs(120))
            .unwrap(),
        1
    );
    let statuses = db
        .lock()
        .unwrap()
        .prepare("SELECT id, status FROM scans ORDER BY id")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        statuses,
        vec![
            (stale, "interrupted".to_owned()),
            (fresh, "running".to_owned())
        ]
    );
    assert!(db.reopen_scan(fresh).is_err());
    assert!(db.reopen_scan(stale).is_ok());
    assert_eq!(db.refresh_wildcard_candidate_count(stale).unwrap(), 0);
    assert_eq!(db.refresh_wildcard_candidate_count(fresh).unwrap(), 1);
}

#[test]
fn indeterminate_scan_candidates_retry_three_times_then_become_terminal() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.persist_scan_candidates(
        scan_id,
        "example.com",
        &[
            ("deferred".to_owned(), "test".to_owned(), 10),
            ("negative".to_owned(), "test".to_owned(), 9),
        ],
    )
    .unwrap();
    let first_claim = db.pending_scan_candidates(scan_id, 10).unwrap();
    db.mark_scan_candidates_started(
        scan_id,
        &first_claim
            .iter()
            .map(|row| format!("{}.example.com", row.0))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    db.update_cache_outcomes(
        Some(scan_id),
        &[],
        &["negative.example.com".to_owned()],
        &["deferred.example.com".to_owned()],
        300,
    )
    .unwrap();
    db.mark_scan_candidates_done(
        scan_id,
        &[
            "deferred.example.com".to_owned(),
            "negative.example.com".to_owned(),
        ],
    )
    .unwrap();

    let second_claim = db.pending_scan_candidates(scan_id, 10).unwrap();
    assert_eq!(
        second_claim
            .iter()
            .map(|(name, _, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["deferred"]
    );
    db.mark_scan_candidates_started(scan_id, &["deferred.example.com".to_owned()])
        .unwrap();
    db.update_cache_outcomes(
        Some(scan_id),
        &[],
        &[],
        &["deferred.example.com".to_owned()],
        300,
    )
    .unwrap();
    db.mark_scan_candidates_done(scan_id, &["deferred.example.com".to_owned()])
        .unwrap();
    let third_claim = db.pending_scan_candidates(scan_id, 10).unwrap();
    assert_eq!(
        third_claim
            .iter()
            .map(|(name, _, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["deferred"]
    );
    db.mark_scan_candidates_started(scan_id, &["deferred.example.com".to_owned()])
        .unwrap();
    db.update_cache_outcomes(
        Some(scan_id),
        &[],
        &[],
        &["deferred.example.com".to_owned()],
        300,
    )
    .unwrap();
    db.mark_scan_candidates_done(scan_id, &["deferred.example.com".to_owned()])
        .unwrap();
    assert!(db.pending_scan_candidates(scan_id, 10).unwrap().is_empty());
    let negative_status: String = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status FROM scan_candidates WHERE scan_id=?1 AND relative_name='negative'",
            [scan_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(negative_status, "done");
    let (deferred_status, attempts): (String, i64) = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT status,attempts FROM scan_candidates WHERE scan_id=?1 AND relative_name='deferred'",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
    assert_eq!(deferred_status, "done");
    assert_eq!(attempts, 3);
}

#[test]
fn a_new_scan_supersedes_only_abandoned_queues_and_preserves_inventory() {
    let db = Database::in_memory().unwrap();
    db.import_inventory(
        "example.com",
        &BTreeSet::from(["api.example.com".to_owned()]),
        "import:test",
    )
    .unwrap();

    let abandoned = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(abandoned, "example.com", "running", "old")
        .unwrap();
    db.persist_scan_candidates(
        abandoned,
        "example.com",
        &[("old".to_owned(), "test".to_owned(), 1)],
    )
    .unwrap();
    db.mark_scan_candidate_feed_exhausted(abandoned, "high-value")
        .unwrap();
    db.finish_scan(abandoned, "interrupted", 1, 0, 0, 1, &[])
        .unwrap();

    let active = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(active, "example.com", "running", "active")
        .unwrap();
    db.persist_scan_candidates(
        active,
        "example.com",
        &[("active".to_owned(), "test".to_owned(), 1)],
    )
    .unwrap();

    let newest = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(newest, "example.com", "running", "new")
        .unwrap();
    assert_eq!(
        db.supersede_incomplete_candidate_queues(
            "example.com",
            newest,
            std::time::Duration::from_secs(120),
        )
        .unwrap(),
        1
    );

    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1",
                [abandoned],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1",
                [active],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    let abandoned_state: (String, String, i64) = connection
        .query_row(
            r#"SELECT scan.status, checkpoint.stage, checkpoint.completed
                   FROM scans AS scan
                   JOIN scan_checkpoints AS checkpoint ON checkpoint.scan_id=scan.id
                   WHERE scan.id=?1"#,
            [abandoned],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        abandoned_state,
        ("superseded".to_owned(), "superseded".to_owned(), 1)
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT completed FROM scan_checkpoints WHERE scan_id=?1",
                [newest],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM subdomains WHERE fqdn='api.example.com'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn superseded_queue_cleanup_is_bounded_and_resumable() {
    let db = Database::in_memory().unwrap();
    let abandoned = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(abandoned, "example.com", "running", "old")
        .unwrap();
    let candidates = (0..2_505)
        .map(|index| (format!("old-{index}"), "test".to_owned(), 1))
        .collect::<Vec<_>>();
    db.persist_scan_candidates(abandoned, "example.com", &candidates)
        .unwrap();
    db.finish_scan(abandoned, "interrupted", candidates.len(), 0, 0, 1, &[])
        .unwrap();

    let newest = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(newest, "example.com", "running", "new")
        .unwrap();
    assert_eq!(
        db.supersede_incomplete_candidate_queues(
            "example.com",
            newest,
            std::time::Duration::from_secs(120),
        )
        .unwrap(),
        2_000
    );
    assert_eq!(db.scan_candidate_count(abandoned).unwrap(), 505);
    assert_eq!(db.prune_superseded_candidate_queues(500).unwrap(), 500);
    assert_eq!(db.scan_candidate_count(abandoned).unwrap(), 5);
    assert_eq!(db.prune_superseded_candidate_queues(100).unwrap(), 5);
    assert_eq!(db.scan_candidate_count(abandoned).unwrap(), 0);
}

#[test]
fn confirmed_wildcard_cleanup_quarantines_all_exact_matches_and_keeps_audit() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let answer = |fqdn: &str| ResolvedHost {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "203.0.113.10".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let finding = |fqdn: &str, source: &str| Finding {
        fqdn: fqdn.to_owned(),
        records: answer(fqdn).records,
        sources: BTreeSet::from([source.to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(&BTreeSet::from([source.to_owned()]), false, false),
        state: ObservationState::Live,
        last_verified_at: Some(now_epoch()),
        evidence_families: BTreeSet::new(),
        authoritative_validation: false,
        ..Finding::default()
    };
    let generated = "generated.example.com";
    let cached_only = "cached-only.example.com";
    let observed = "observed.example.com";
    db.persist_findings(
        scan_id,
        "example.com",
        &[
            finding(generated, "dns-wave-2"),
            finding(observed, "passive:subdomainapp"),
        ],
        86_400,
    )
    .unwrap();
    db.update_cache_outcomes(
        Some(scan_id),
        &[answer(generated), answer(cached_only), answer(observed)],
        &[],
        &[],
        300,
    )
    .unwrap();
    db.store_observations(
        "example.com",
        vec![
            ObservationInput {
                fqdn: generated.to_owned(),
                kind: "dns-wave-2".to_owned(),
                source: "dns-wave-2".to_owned(),
                value: String::new(),
            },
            ObservationInput {
                fqdn: observed.to_owned(),
                kind: "passive".to_owned(),
                source: "passive:subdomainapp".to_owned(),
                value: String::new(),
            },
        ],
    )
    .unwrap();
    db.record_current_wildcard_matches(
        scan_id,
        &[answer(generated), answer(cached_only), answer(observed)],
    )
    .unwrap();
    let purged = db
        .purge_confirmed_wildcard_false_positives(
            scan_id,
            "example.com",
            &[
                generated.to_owned(),
                cached_only.to_owned(),
                observed.to_owned(),
            ],
        )
        .unwrap();
    assert_eq!(purged, vec![cached_only, generated, observed]);
    assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
    assert!(
        db.fresh_cache(&[
            generated.to_owned(),
            cached_only.to_owned(),
            observed.to_owned(),
        ])
        .unwrap()
        .is_empty()
    );
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM observed_names WHERE fqdn=?1",
                [generated],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM scan_findings WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM scan_findings WHERE scan_id=?1 AND fqdn=?2",
                params![scan_id, generated],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM dns_records WHERE fqdn=?1",
                [generated],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT active FROM dns_records WHERE fqdn=?1",
                [generated],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT found FROM scans WHERE id=?1", [scan_id], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM wildcard_quarantine WHERE root_domain='example.com'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        3
    );
}

#[test]
fn wildcard_marker_is_cache_independent_and_hashes_records_without_ttl_or_order() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let mut answer = ResolvedHost {
        fqdn: "candidate.example.com".to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 1,
    };
    assert_eq!(
        db.record_current_wildcard_matches(scan_id, &[answer.clone()])
            .unwrap(),
        0
    );
    answer.authoritative_validation = true;
    assert_eq!(
        db.record_current_wildcard_matches(scan_id, &[answer.clone()])
            .unwrap(),
        1,
        "an authoritative current answer is equivalent to resolver consensus"
    );
    answer.authoritative_validation = false;
    answer.resolver_count = 2;
    answer.records.clear();
    assert_eq!(
        db.record_current_wildcard_matches(scan_id, &[answer.clone()])
            .unwrap(),
        0
    );
    answer.records.push(DnsRecord {
        record_type: "A".to_owned(),
        value: "192.0.2.44".to_owned(),
        ttl: 60,
    });
    answer.records.push(DnsRecord {
        record_type: "CNAME".to_owned(),
        value: "edge.example.net".to_owned(),
        ttl: 120,
    });
    answer.from_cache = true;
    assert_eq!(
        db.record_current_wildcard_matches(scan_id, &[answer.clone()])
            .unwrap(),
        0
    );
    answer.from_cache = false;
    assert_eq!(
        db.record_current_wildcard_matches(scan_id, &[answer.clone()])
            .unwrap(),
        1
    );
    let journal_hash = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT records_hash FROM dns_verifications \
                 WHERE scan_id=?1 AND fqdn=?2 ORDER BY id DESC LIMIT 1",
            params![scan_id, answer.fqdn],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let reordered_with_new_ttls = vec![
        DnsRecord {
            record_type: "cname".to_owned(),
            value: "edge.example.net".to_owned(),
            ttl: 1,
        },
        DnsRecord {
            record_type: "a".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 9_999,
        },
    ];
    assert_eq!(
        journal_hash,
        canonical_dns_records_hash(&reordered_with_new_ttls).unwrap()
    );
    assert_eq!(
            db.purge_confirmed_wildcard_false_positives(
                scan_id,
                "example.com",
                &[answer.fqdn.clone()],
            )
            .unwrap(),
            vec![answer.fqdn.clone()],
            "cleanup authorization must not require a positive dns_cache row"
        );
    let explanation = db.explain(&answer.fqdn).unwrap();
    assert_eq!(explanation["known"], true);
    assert_eq!(explanation["quarantine"].as_array().unwrap().len(), 1);
    assert!(
        db.purge_confirmed_wildcard_false_positives(
            scan_id,
            "example.com",
            &["outside.example.net".to_owned()],
        )
        .is_err()
    );
}

#[test]
fn wildcard_ambiguity_is_unverified_without_a_resolver_error() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "rotating.example.com";
    let answer = ResolvedHost {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let sources = BTreeSet::from(["passive:test".to_owned()]);
    db.persist_findings(
        scan_id,
        "example.com",
        &[Finding {
            fqdn: fqdn.to_owned(),
            records: answer.records.clone(),
            sources: sources.clone(),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(&sources, false, false),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::new(),
            authoritative_validation: false,
            ..Finding::default()
        }],
        86_400,
    )
    .unwrap();
    db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 300)
        .unwrap();

    assert_eq!(
        db.record_current_wildcard_ambiguities(
            scan_id,
            "example.com",
            std::slice::from_ref(&answer),
        )
        .unwrap(),
        1
    );
    assert!(
        !db.fresh_cache(&[fqdn.to_owned()])
            .unwrap()
            .contains_key(fqdn)
    );
    let inventory = db.inventory(Some("example.com"), false).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].state, ObservationState::Unverified);
    let connection = db.lock().unwrap();
    let (outcome, details): (String, String) = connection
        .query_row(
            r#"SELECT outcome, details_json FROM dns_verifications
                   WHERE scan_id=?1 AND fqdn=?2 ORDER BY id DESC LIMIT 1"#,
            params![scan_id, fqdn],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(outcome, "unverified");
    assert_eq!(details, CURRENT_SCAN_WILDCARD_AMBIGUITY_DETAILS);
    assert_eq!(
        connection
            .query_row(
                "SELECT active FROM dns_records WHERE fqdn=?1",
                [fqdn],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn wildcard_quarantine_is_root_scoped_hidden_and_reversible() {
    let db = Database::in_memory().unwrap();
    let parent_scan = db.create_scan("example.com", &json!({})).unwrap();
    let child_scan = db.create_scan("sub.example.com", &json!({})).unwrap();
    let fqdn = "api.sub.example.com";
    let answer = ResolvedHost {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.70".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let finding = Finding {
        fqdn: fqdn.to_owned(),
        records: answer.records.clone(),
        sources: BTreeSet::from(["dns-wave-2".to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(
            &BTreeSet::from(["dns-wave-2".to_owned()]),
            false,
            false,
        ),
        state: ObservationState::Live,
        last_verified_at: answer.last_verified_at,
        evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
        authoritative_validation: false,
        ..Finding::default()
    };
    db.persist_findings(
        parent_scan,
        "example.com",
        std::slice::from_ref(&finding),
        86_400,
    )
    .unwrap();
    db.record_current_wildcard_matches(parent_scan, std::slice::from_ref(&answer))
        .unwrap();
    db.record_current_wildcard_matches(child_scan, std::slice::from_ref(&answer))
        .unwrap();
    assert_eq!(
            db.purge_confirmed_wildcard_false_positives(
                parent_scan,
                "example.com",
                &[fqdn.to_owned()],
            )
            .unwrap(),
            vec![fqdn]
        );
    assert_eq!(
        db.purge_confirmed_wildcard_false_positives(
            child_scan,
            "sub.example.com",
            &[fqdn.to_owned()],
        )
        .unwrap(),
        vec![fqdn]
    );
    assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
    let explanation = db.explain(fqdn).unwrap();
    assert_eq!(explanation["quarantine"].as_array().unwrap().len(), 2);
    assert_eq!(explanation["scan_history"].as_array().unwrap().len(), 1);

    db.persist_findings(parent_scan, "example.com", &[finding], 86_400)
        .unwrap();
    assert_eq!(db.inventory(Some("example.com"), false).unwrap().len(), 1);
    let connection = db.lock().unwrap();
    let mut statement = connection
        .prepare("SELECT root_domain FROM wildcard_quarantine WHERE fqdn=?1 ORDER BY root_domain")
        .unwrap();
    let quarantined_roots = statement
        .query_map([fqdn], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(quarantined_roots, vec!["sub.example.com"]);
}

#[test]
fn wildcard_consensus_quarantines_despite_independent_passive_evidence() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "api.example.com";
    let answer = ResolvedHost {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.80".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let sources = BTreeSet::from(["dns-wave-2".to_owned()]);
    db.persist_findings(
        scan_id,
        "example.com",
        &[Finding {
            fqdn: fqdn.to_owned(),
            records: answer.records.clone(),
            sources: sources.clone(),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(&sources, false, false),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            authoritative_validation: false,
            ..Finding::default()
        }],
        86_400,
    )
    .unwrap();
    db.record_current_wildcard_matches(scan_id, std::slice::from_ref(&answer))
        .unwrap();
    assert_eq!(
        db.purge_confirmed_wildcard_false_positives(scan_id, "example.com", &[fqdn.to_owned()],)
            .unwrap(),
        vec![fqdn]
    );
    assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
    db.store_observations(
        "archive.example.net",
        vec![ObservationInput {
            fqdn: fqdn.to_owned(),
            kind: "passive".to_owned(),
            source: "passive:cross-root".to_owned(),
            value: String::new(),
        }],
    )
    .unwrap();
    db.record_current_wildcard_matches(scan_id, &[answer])
        .unwrap();
    assert_eq!(
        db.purge_confirmed_wildcard_false_positives(scan_id, "example.com", &[fqdn.to_owned()],)
            .unwrap(),
        vec![fqdn]
    );
    assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM wildcard_quarantine WHERE fqdn=?1",
                [fqdn],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM observation_evidence WHERE source='passive:cross-root'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
        "quarantine must preserve passive evidence for explain/audit"
    );
}

#[test]
fn refresh_wildcard_staging_accepts_large_inventories_in_bounded_batches() {
    let db = Database::in_memory().unwrap();
    let scan_id = db
        .create_scan("example.com", &json!({"mode": "refresh"}))
        .unwrap();
    let names = (0..20_000)
        .map(|index| format!("candidate-{index:05}.example.com"))
        .collect::<Vec<_>>();
    for page in names.chunks(257) {
        db.stage_refresh_wildcard_candidates(scan_id, page).unwrap();
    }
    assert_eq!(
        db.refresh_wildcard_candidate_count(scan_id).unwrap(),
        20_000
    );
    assert_eq!(
        db.stage_refresh_wildcard_candidates(scan_id, &names[..500])
            .unwrap(),
        0,
        "staging is idempotent across overlapping refresh pages"
    );
    assert_eq!(
        db.discard_refresh_wildcard_candidates(scan_id).unwrap(),
        20_000
    );
    assert_eq!(db.refresh_wildcard_candidate_count(scan_id).unwrap(), 0);
}

#[test]
fn cached_wildcard_match_without_current_network_marker_is_demoted_not_deleted() {
    let db = Database::in_memory().unwrap();
    let scan_id = db
        .create_scan("example.com", &json!({"mode": "refresh"}))
        .unwrap();
    let fqdn = "cached.example.com";
    let answer = ResolvedHost {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let finding = Finding {
        fqdn: fqdn.to_owned(),
        records: answer.records.clone(),
        sources: BTreeSet::from(["dns-wave-2".to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(
            &BTreeSet::from(["dns-wave-2".to_owned()]),
            false,
            false,
        ),
        state: ObservationState::Live,
        last_verified_at: answer.last_verified_at,
        evidence_families: BTreeSet::new(),
        authoritative_validation: false,
        ..Finding::default()
    };
    db.persist_findings(scan_id, "example.com", &[finding], 86_400)
        .unwrap();
    // An ordinary historical/live journal row and a positive cache entry
    // are intentionally insufficient: cleanup requires the dedicated
    // current-scan network wildcard marker.
    db.update_cache_outcomes(Some(scan_id), &[answer], &[], &[], 300)
        .unwrap();
    db.stage_refresh_wildcard_candidates(scan_id, &[fqdn.to_owned()])
        .unwrap();

    let result = db
        .apply_staged_refresh_wildcard_cleanup(scan_id, "example.com", 1, &AtomicBool::new(false))
        .unwrap()
        .unwrap();
    assert_eq!(
        result,
        WildcardCleanupResult {
            purged: 0,
            retained_unverified: 1,
        }
    );
    let inventory = db.inventory(Some("example.com"), false).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].state, ObservationState::Unverified);
    assert!(matches!(
        db.fresh_cache(&[fqdn.to_owned()]).unwrap().get(fqdn),
        Some(CachedAnswer::Positive(_))
    ));
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM dns_records WHERE fqdn=?1",
                [fqdn],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT active FROM dns_records WHERE fqdn=?1",
                [fqdn],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn cancelled_staged_wildcard_cleanup_rolls_back_every_destructive_change() {
    let db = Database::in_memory().unwrap();
    let original_scan = db.create_scan("example.com", &json!({})).unwrap();
    let refresh_scan = db
        .create_scan("example.com", &json!({"mode": "refresh"}))
        .unwrap();
    let make = |fqdn: &str, source: &str| Finding {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        sources: BTreeSet::from([source.to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(&BTreeSet::from([source.to_owned()]), false, false),
        state: ObservationState::Live,
        last_verified_at: Some(now_epoch()),
        evidence_families: BTreeSet::new(),
        authoritative_validation: false,
        ..Finding::default()
    };
    let mut findings = vec![make("a-independent.example.com", "passive:crtsh")];
    findings
        .extend((0..12).map(|index| make(&format!("weak-{index:02}.example.com"), "dns-wave-2")));
    db.persist_findings(original_scan, "example.com", &findings, 86_400)
        .unwrap();
    db.finish_scan(
        original_scan,
        "completed",
        findings.len(),
        findings.len(),
        0,
        1,
        &[],
    )
    .unwrap();
    let names = findings
        .iter()
        .map(|finding| finding.fqdn.clone())
        .collect::<Vec<_>>();
    let wildcard_answers = names
        .iter()
        .map(|fqdn| ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        })
        .collect::<Vec<_>>();
    db.record_current_wildcard_matches(refresh_scan, &wildcard_answers)
        .unwrap();
    db.stage_refresh_wildcard_candidates(refresh_scan, &names)
        .unwrap();

    let result = db
        .apply_staged_refresh_wildcard_cleanup_with_cancel(
            refresh_scan,
            "example.com",
            2,
            |processed| processed >= 3,
        )
        .unwrap();
    assert!(result.is_none());
    assert_eq!(
        db.refresh_wildcard_candidate_count(refresh_scan).unwrap(),
        findings.len(),
        "a rolled-back transaction leaves staging available for explicit discard"
    );
    let inventory = db.inventory(Some("example.com"), false).unwrap();
    assert_eq!(inventory.len(), findings.len());
    assert!(
        inventory
            .iter()
            .all(|entry| entry.state == ObservationState::Live)
    );
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM scan_findings WHERE scan_id=?1",
                [original_scan],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        findings.len() as i64
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT found FROM scans WHERE id=?1",
                [original_scan],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        findings.len() as i64
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM dns_verifications WHERE scan_id=?1",
                [refresh_scan],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        findings.len() as i64
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM dns_records WHERE fqdn LIKE '%.example.com'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        findings.len() as i64,
        "record deactivation/deletion must roll back with inventory cleanup"
    );
    drop(connection);

    let applied = db
        .apply_staged_refresh_wildcard_cleanup(
            refresh_scan,
            "example.com",
            2,
            &AtomicBool::new(false),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        applied,
        WildcardCleanupResult {
            purged: 13,
            retained_unverified: 0,
        }
    );
    assert_eq!(
        db.refresh_wildcard_candidate_count(refresh_scan).unwrap(),
        0
    );
    assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
    let connection = db.lock().unwrap();
    let (finding_count, changed_findings, found): (i64, i64, i64) = connection
        .query_row(
            r#"SELECT COUNT(*),
                          SUM(CASE WHEN finding.wildcard<>0 OR finding.state<>'live'
                                   THEN 1 ELSE 0 END),
                          scans.found
                   FROM scan_findings finding
                   JOIN scans ON scans.id=finding.scan_id
                   WHERE finding.scan_id=?1"#,
            [original_scan],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((finding_count, changed_findings, found), (13, 0, 13));
    let (records, active_records): (i64, i64) = connection
        .query_row(
            r#"SELECT COUNT(*), COALESCE(SUM(active), 0) FROM dns_records
                   WHERE fqdn LIKE '%.example.com'"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((records, active_records), (13, 0));
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM wildcard_quarantine WHERE root_domain='example.com'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        13
    );
}

#[test]
fn cancelled_staged_cleanup_never_waits_for_the_shared_database_lock() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.stage_refresh_wildcard_candidates(scan_id, &["weak.example.com".to_owned()])
        .unwrap();

    let held_lock = db.lock().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let worker_db = db.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = worker_db.apply_staged_refresh_wildcard_cleanup(
            scan_id,
            "example.com",
            1,
            &worker_cancelled,
        );
        let _ = result_tx.send(result);
    });

    std::thread::sleep(Duration::from_millis(25));
    cancelled.store(true, Ordering::Release);
    let result = result_rx.recv_timeout(Duration::from_millis(500));
    drop(held_lock);
    worker.join().unwrap();

    assert!(
        result
            .expect("cleanup ignored cancellation while waiting for SQLite")
            .unwrap()
            .is_none()
    );
    assert_eq!(db.refresh_wildcard_candidate_count(scan_id).unwrap(), 1);
}

#[test]
fn candidate_attempt_counters_saturate_at_sqlite_integer_max() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let active = "active.example.com";
    let recursive = "recursive.example.com";
    db.lock()
        .unwrap()
        .execute(
            r#"INSERT INTO scan_candidates(
                       scan_id, fqdn, relative_name, priority, generator, attempts, status
                   ) VALUES (?1, ?2, 'active', 1, 'fixture', ?3, 'processing')"#,
            params![scan_id, active, i64::MAX],
        )
        .unwrap();
    db.lock()
        .unwrap()
        .execute(
            r#"INSERT INTO scan_recursive_candidates(
                       scan_id, fqdn, parent, depth, word, attempts, status
                   ) VALUES (?1, ?2, 'example.com', 2, 'recursive', ?3, 'processing')"#,
            params![scan_id, recursive, i64::MAX],
        )
        .unwrap();

    db.mark_scan_candidates_started(scan_id, &[active.to_owned()])
        .unwrap();
    db.mark_scan_recursive_candidates_started(scan_id, &[recursive.to_owned()])
        .unwrap();

    let connection = db.lock().unwrap();
    for (table, fqdn) in [
        ("scan_candidates", active),
        ("scan_recursive_candidates", recursive),
    ] {
        let query =
            format!("SELECT attempts, typeof(attempts) FROM {table} WHERE scan_id=?1 AND fqdn=?2");
        let (attempts, value_type): (i64, String) = connection
            .query_row(&query, params![scan_id, fqdn], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(attempts, i64::MAX);
        assert_eq!(value_type, "integer");
    }
}

#[test]
fn scan_snapshot_replaces_rows_and_late_heartbeat_cannot_reopen_completion() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let make = |fqdn: &str| Finding {
        fqdn: fqdn.to_owned(),
        records: Vec::new(),
        sources: BTreeSet::from(["passive:test".to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(
            &BTreeSet::from(["passive:test".to_owned()]),
            false,
            false,
        ),
        state: ObservationState::Unverified,
        last_verified_at: None,
        evidence_families: BTreeSet::new(),
        authoritative_validation: false,
        ..Finding::default()
    };
    let first = make("one.example.com");
    let second = make("two.example.com");
    db.persist_findings(
        scan_id,
        "example.com",
        &[first.clone(), second.clone()],
        86_400,
    )
    .unwrap();
    db.persist_scan_snapshot(scan_id, std::slice::from_ref(&first))
        .unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "options")
        .unwrap();
    db.finalize_scan(scan_id, 2, 1, 0, 1, &[]).unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "options")
        .unwrap();
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM scan_findings WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT completed FROM scan_checkpoints WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn non_resumable_refresh_finalization_closes_its_checkpoint() {
    let db = Database::in_memory().unwrap();
    let scan_id = db
        .create_scan("example.com", &json!({"mode": "refresh"}))
        .unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "refresh-options")
        .unwrap();
    db.finalize_non_resumable_scan(
        scan_id,
        "interrupted",
        12,
        3,
        0,
        25,
        &["interrupted safely".to_owned()],
    )
    .unwrap();

    assert!(
        db.resumable_checkpoint("example.com", "latest")
            .unwrap()
            .is_none()
    );
    let connection = db.lock().unwrap();
    let (status, completed) = connection
        .query_row(
            r#"SELECT scans.status, checkpoint.completed
                   FROM scans JOIN scan_checkpoints checkpoint ON checkpoint.scan_id=scans.id
                   WHERE scans.id=?1"#,
            [scan_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap();
    assert_eq!(status, "interrupted");
    assert_eq!(completed, 1);
}

#[test]
fn active_budget_pause_keeps_checkpoint_feeds_and_candidates_resumable() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "options")
        .unwrap();
    db.persist_scan_candidates(
        scan_id,
        "example.com",
        &[("pending".to_owned(), "builtin".to_owned(), 10)],
    )
    .unwrap();
    db.mark_scan_candidate_feed_exhausted(scan_id, "wordlist")
        .unwrap();

    db.pause_scan(scan_id, 1, 0, 0, 25, &["budget reached".to_owned()])
        .unwrap();

    let checkpoint = db
        .resumable_checkpoint("example.com", "latest")
        .unwrap()
        .expect("partial scan checkpoint was closed");
    assert_eq!(checkpoint.scan_id, scan_id);
    assert_eq!(checkpoint.stage, "paused");
    assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 1);
    let (status, learning_applied): (String, i64) = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status,learning_applied FROM scans WHERE id=?1",
            [scan_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((status.as_str(), learning_applied), ("interrupted", 0));
    db.reopen_scan(scan_id).unwrap();
    assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 1);
}

#[test]
fn refresh_inventory_pages_are_stable_and_cache_only_pages_exclude_inventory() {
    let db = Database::in_memory().unwrap();
    let names = BTreeSet::from([
        "a.example.com".to_owned(),
        "b.example.com".to_owned(),
        "c.example.com".to_owned(),
        "d.example.com".to_owned(),
        "e.example.com".to_owned(),
    ]);
    db.import_inventory("example.com", &names, "import:test")
        .unwrap();
    assert_eq!(db.known_subdomain_count("example.com", true).unwrap(), 5);

    let first = db
        .known_subdomains_page("example.com", true, None, 2)
        .unwrap();
    let second = db
        .known_subdomains_page("example.com", true, first.last().map(String::as_str), 2)
        .unwrap();
    let third = db
        .known_subdomains_page("example.com", true, second.last().map(String::as_str), 2)
        .unwrap();
    assert_eq!(
        first
            .into_iter()
            .chain(second)
            .chain(third)
            .collect::<Vec<_>>(),
        names.iter().cloned().collect::<Vec<_>>()
    );
    let first_inventory = db.inventory_page("example.com", false, None, 3).unwrap();
    let second_inventory = db
        .inventory_page(
            "example.com",
            false,
            first_inventory.last().map(|entry| entry.fqdn.as_str()),
            3,
        )
        .unwrap();
    assert_eq!(
        first_inventory
            .into_iter()
            .chain(second_inventory)
            .map(|entry| entry.fqdn)
            .collect::<Vec<_>>(),
        names.iter().cloned().collect::<Vec<_>>()
    );

    let cached_only = ResolvedHost {
        fqdn: "cache-only.example.com".to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.55".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 1,
    };
    let inventory_answer = ResolvedHost {
        fqdn: names.iter().next().unwrap().clone(),
        ..cached_only.clone()
    };
    db.update_cache_outcomes(None, &[cached_only, inventory_answer], &[], &[], 300)
        .unwrap();
    assert_eq!(
        db.positive_cache_only_names_page("example.com", None, 10)
            .unwrap(),
        vec!["cache-only.example.com"]
    );
    assert_eq!(db.positive_cache_only_count("example.com").unwrap(), 1);
}

#[test]
fn current_negative_inventory_is_hidden_but_preserved_and_can_return_live() {
    let db = Database::in_memory().unwrap();
    let fqdn = "retired.example.com".to_owned();
    db.import_inventory(
        "example.com",
        &BTreeSet::from([fqdn.clone()]),
        "passive:test",
    )
    .unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();

    db.record_discovery_negatives(scan_id, std::slice::from_ref(&fqdn))
        .unwrap();

    let retained = db.inventory(Some("example.com"), false).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].fqdn, fqdn);
    assert!(
        db.current_inventory_page("example.com", false, None, 10)
            .unwrap()
            .is_empty()
    );
    let explanation = db.explain(&fqdn).unwrap();
    assert_eq!(explanation["known"], true);
    assert_eq!(explanation["inventory"]["state"], "unverified");
    assert_eq!(
        explanation["dns_verifications"]
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry["outcome"].as_str()),
        Some("negative")
    );

    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.90".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: true,
        resolver_count: 2,
    };
    db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 300)
        .unwrap();
    let sources = BTreeSet::from(["live_dns".to_owned()]);
    db.persist_findings(
        scan_id,
        "example.com",
        &[Finding {
            fqdn: fqdn.clone(),
            records: answer.records,
            sources: sources.clone(),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(&sources, false, true),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            authoritative_validation: true,
            ..Finding::default()
        }],
        86_400,
    )
    .unwrap();

    let inventory = db.inventory(Some("example.com"), false).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].fqdn, fqdn);
    assert_eq!(inventory[0].state, ObservationState::Live);
}

#[test]
fn later_negative_overrides_old_positive_cache_and_live_inventory_for_current_output() {
    let db = Database::in_memory().unwrap();
    let fqdn = "stale-live.example.com".to_owned();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.91".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: true,
        resolver_count: 2,
    };
    let sources = BTreeSet::from(["live_dns".to_owned()]);
    db.persist_findings(
        scan_id,
        "example.com",
        &[Finding {
            fqdn: fqdn.clone(),
            records: answer.records.clone(),
            sources: sources.clone(),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            authoritative_validation: true,
            ..Finding::default()
        }],
        86_400,
    )
    .unwrap();
    db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 300)
        .unwrap();
    db.record_discovery_negatives(scan_id, std::slice::from_ref(&fqdn))
        .unwrap();

    assert!(matches!(
        db.fresh_cache(std::slice::from_ref(&fqdn))
            .unwrap()
            .get(&fqdn),
        Some(CachedAnswer::Positive(_))
    ));
    assert_eq!(
        db.inventory(Some("example.com"), false).unwrap()[0].state,
        ObservationState::Live,
        "the append-only audit preserves the prior materialized state"
    );
    assert!(db.inventory(Some("example.com"), true).unwrap().is_empty());
    assert!(
        db.current_output_names(std::slice::from_ref(&fqdn))
            .unwrap()
            .is_empty()
    );
    assert!(
        db.current_inventory_page("example.com", false, None, 10)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.explain(&fqdn).unwrap()["dns_verifications"][0]["outcome"],
        "negative"
    );
}

#[test]
fn final_seed_filter_rejects_negative_and_quarantined_names_without_deleting_audit() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let allowed = "allowed.example.com".to_owned();
    let negative = "negative.example.com".to_owned();
    let quarantined = "quarantined.example.com".to_owned();
    let candidates = [
        (
            allowed.clone(),
            BTreeSet::from(["passive:test".to_owned()]),
            10,
        ),
        (
            negative.clone(),
            BTreeSet::from(["passive:test".to_owned()]),
            10,
        ),
        (
            quarantined.clone(),
            BTreeSet::from(["passive:test".to_owned()]),
            10,
        ),
    ];
    db.persist_scan_seed_candidates(scan_id, &candidates, candidates.len())
        .unwrap();
    db.record_discovery_negatives(scan_id, std::slice::from_ref(&negative))
        .unwrap();
    db.import_inventory(
        "example.com",
        &BTreeSet::from([quarantined.clone()]),
        "passive:test",
    )
    .unwrap();
    let wildcard_answer = ResolvedHost {
        fqdn: quarantined.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.92".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    db.record_current_wildcard_matches(scan_id, &[wildcard_answer])
        .unwrap();
    assert_eq!(
        db.purge_confirmed_wildcard_false_positives(
            scan_id,
            "example.com",
            std::slice::from_ref(&quarantined),
        )
        .unwrap(),
        vec![quarantined.as_str()]
    );

    let all_seeds = db.scan_seed_candidates_for_output(scan_id).unwrap();
    assert_eq!(all_seeds.len(), 3, "the durable audit queue is retained");
    let current = db
        .current_seed_output_names(
            "example.com",
            &all_seeds
                .iter()
                .map(|(fqdn, _)| fqdn.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    assert_eq!(current, BTreeSet::from([allowed]));
    assert!(
        db.inventory(Some("example.com"), false)
            .unwrap()
            .iter()
            .all(|entry| entry.fqdn != quarantined),
        "quarantined wildcard names stay out of every inventory listing"
    );
    assert!(db.inventory(Some("example.com"), true).unwrap().is_empty());
    assert_eq!(
        db.explain(&quarantined).unwrap()["quarantine"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn wordlists_are_streamed_deduplicated_and_bounded_in_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let wordlist = directory.path().join("words.txt");
    std::fs::write(&wordlist, "www\napi\nwww\ninvalid name\nadmin\n").unwrap();
    let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let (inserted, exhausted) = db
        .refill_wordlist_candidates(scan_id, "example.com", &wordlist, 2)
        .unwrap();
    assert_eq!(inserted, 2);
    assert!(!exhausted);
    assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 2);
    let candidates = db.pending_scan_candidates(scan_id, 2).unwrap();
    assert_eq!(
        candidates
            .into_iter()
            .map(|(name, _, _)| name)
            .collect::<Vec<_>>(),
        vec!["www", "api"]
    );
    db.mark_scan_candidates_done(
        scan_id,
        &["www.example.com".to_owned(), "api.example.com".to_owned()],
    )
    .unwrap();
    let (inserted, exhausted) = db
        .refill_wordlist_candidates(scan_id, "example.com", &wordlist, 2)
        .unwrap();
    assert_eq!(inserted, 1);
    assert!(exhausted);
    assert_eq!(
        db.pending_scan_candidate_count(scan_id).unwrap(),
        1,
        "only the requested page may be queued"
    );
    assert_eq!(db.scan_candidate_count(scan_id).unwrap(), 3);
}

#[test]
fn wordlist_page_tracks_the_scheduler_batch_and_resumes_at_its_exact_cursor() {
    let directory = tempfile::tempdir().unwrap();
    let wordlist = directory.path().join("batch-words.txt");
    let database_path = directory.path().join("fellaga.db");
    let words = (0..5_000)
        .map(|index| format!("batch-{index}"))
        .collect::<Vec<_>>();
    let expected_first_cursor = words[..4_096]
        .iter()
        .map(|word| word.len() + 1)
        .sum::<usize>() as i64;
    std::fs::write(&wordlist, format!("{}\n", words.join("\n"))).unwrap();

    let db = Database::open(&database_path).unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    assert_eq!(
        db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 4_096)
            .unwrap(),
        (4_096, false)
    );
    assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 4_096);
    let first_cursor: i64 = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT cursor FROM scan_candidate_feeds WHERE scan_id=?1 AND source='wordlist'",
            [scan_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(first_cursor, expected_first_cursor);
    drop(db);

    let reopened = Database::open(&database_path).unwrap();
    assert_eq!(
        reopened
            .refill_wordlist_candidates(scan_id, "example.com", &wordlist, 4_096)
            .unwrap(),
        (904, true)
    );
    assert_eq!(reopened.scan_candidate_count(scan_id).unwrap(), 5_000);
    assert!(
        reopened
            .scan_candidate_feed_exhausted(scan_id, "wordlist")
            .unwrap()
    );
}

#[test]
fn non_utf8_wordlist_lines_are_skipped_without_aborting_the_page() {
    let directory = tempfile::tempdir().unwrap();
    let wordlist = directory.path().join("binary-words.txt");
    std::fs::write(&wordlist, b"www\ninvalid-\xff-name\napi\r\n").unwrap();
    let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();

    assert_eq!(
        db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 10)
            .unwrap(),
        (2, true)
    );
    assert_eq!(
        db.pending_scan_candidates(scan_id, 10)
            .unwrap()
            .into_iter()
            .map(|(name, _, _)| name)
            .collect::<Vec<_>>(),
        vec!["www", "api"]
    );
}

#[test]
fn invalid_heavy_wordlist_pages_have_a_hard_read_budget() {
    let directory = tempfile::tempdir().unwrap();
    let wordlist = directory.path().join("mostly-invalid.txt");
    let mut content = "invalid name\n".repeat(1_500);
    content.push_str("api\n");
    std::fs::write(&wordlist, content).unwrap();
    let file_size = std::fs::metadata(&wordlist).unwrap().len() as i64;
    let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();

    let first = db
        .refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
        .unwrap();
    assert_eq!(first, (0, false));
    let first_cursor: i64 = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT cursor FROM scan_candidate_feeds WHERE scan_id=?1 AND source='wordlist'",
            [scan_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(first_cursor > 0);
    assert!(
        first_cursor < file_size,
        "one refill must not scan the whole file"
    );

    assert_eq!(
        db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
            .unwrap(),
        (1, true)
    );
    assert_eq!(
        db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
            .unwrap(),
        (0, true)
    );
}

#[test]
fn a_single_oversized_wordlist_line_is_discarded_in_bounded_pages() {
    let directory = tempfile::tempdir().unwrap();
    let wordlist = directory.path().join("oversized-line.txt");
    let mut content = vec![b'a'; 4 * 1024 * 1024 + 128];
    content.extend_from_slice(b"\napi\n");
    std::fs::write(&wordlist, content).unwrap();
    let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();

    assert_eq!(
        db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
            .unwrap(),
        (0, false)
    );
    let (cursor, state): (i64, String) = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT cursor,cursor_text FROM scan_candidate_feeds WHERE scan_id=?1 AND source='wordlist'",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
    assert_eq!(cursor, 4 * 1024 * 1024);
    assert_eq!(state, "discard");
    assert_eq!(
        db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
            .unwrap(),
        (1, true)
    );
    assert_eq!(db.scan_candidate_count(scan_id).unwrap(), 1);
    assert_eq!(db.pending_scan_candidates(scan_id, 1).unwrap()[0].0, "api");
}

#[test]
fn opening_an_existing_v8_database_repairs_columns_before_dependent_indexes() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let connection = Connection::open(temporary.path()).unwrap();
    connection
        .execute_batch(
            r#"
                CREATE TABLE scan_candidates (
                    scan_id INTEGER NOT NULL,
                    fqdn TEXT NOT NULL,
                    relative_name TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    generator TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    PRIMARY KEY(scan_id, fqdn)
                );
                PRAGMA user_version=8;
                "#,
        )
        .unwrap();
    drop(connection);

    let db = Database::open(temporary.path()).unwrap();
    let connection = db.lock().unwrap();
    let repaired_columns: i64 = connection
        .query_row(
            r#"SELECT COUNT(*) FROM pragma_table_info('scan_candidates')
                   WHERE name IN ('attempts', 'learning_recorded')"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(repaired_columns, 2);
    let objects: i64 = connection
        .query_row(
            r#"SELECT COUNT(*) FROM sqlite_master WHERE
                   (type='table' AND name='scan_candidate_feeds') OR
                   (type='index' AND name='idx_scan_candidates_unrecorded')"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(objects, 2);
}

#[test]
fn a_failed_v8_to_v9_migration_rolls_back_every_additive_change() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let connection = Connection::open(temporary.path()).unwrap();
    connection
        .execute_batch(
            r#"
                CREATE TABLE scan_candidates (
                    scan_id INTEGER NOT NULL,
                    fqdn TEXT NOT NULL,
                    relative_name TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    generator TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    PRIMARY KEY(scan_id, fqdn)
                );
                CREATE TABLE migration_state(name TEXT PRIMARY KEY);
                PRAGMA user_version=8;
                "#,
        )
        .unwrap();
    drop(connection);

    assert!(Database::open(temporary.path()).is_err());
    let connection = Connection::open(temporary.path()).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        8
    );
    let repaired_columns: i64 = connection
        .query_row(
            r#"SELECT COUNT(*) FROM pragma_table_info('scan_candidates')
                   WHERE name IN ('attempts', 'learning_recorded')"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(repaired_columns, 0);
    let leaked_tables: i64 = connection
        .query_row(
            r#"SELECT COUNT(*) FROM sqlite_master
                   WHERE type='table' AND name IN (
                       'scan_candidate_feeds', 'scan_seed_candidates',
                       'scan_generator_stats', 'scan_attempted_words'
                   )"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(leaked_tables, 0);
    let leaked_v9_tables: i64 = connection
        .query_row(
            r#"SELECT COUNT(*) FROM sqlite_master
                   WHERE type='table' AND name IN (
                       'discovery_actions', 'intelligence_edges', 'name_templates',
                       'dnssec_proofs', 'ct_tiles', 'scheduler_arms'
                   )"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(leaked_v9_tables, 0);
}

#[test]
fn imported_names_remain_unverified_after_reopening_v9() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    {
        let db = Database::open(temporary.path()).unwrap();
        db.import_inventory(
            "example.com",
            &BTreeSet::from(["api.example.com".to_owned()]),
            "import:test",
        )
        .unwrap();
    }
    let reopened = Database::open(temporary.path()).unwrap();
    let inventory = reopened.inventory(Some("example.com"), false).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].state, ObservationState::Unverified);
    assert_eq!(inventory[0].last_verified_at, None);
}

#[test]
fn legacy_empty_and_failed_axfr_rows_are_reclassified() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    {
        let db = Database::open(temporary.path()).unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let connection = db.lock().unwrap();
        connection
            .execute(
                r#"INSERT INTO axfr_attempts(
                       scan_id, nameserver, address, status, error, record_count, attempted_at
                       ) VALUES (?1, 'ns1.example.com', '192.0.2.53', 'success', NULL, 0, 1)"#,
                [scan_id],
            )
            .unwrap();
        connection
                .execute(
                    r#"INSERT INTO axfr_attempts(
                       scan_id, nameserver, address, status, error, record_count, attempted_at
                       ) VALUES (?1, 'ns2.example.com', '192.0.2.54', 'failed', 'proto error', 0, 1)"#,
                    [scan_id],
                )
                .unwrap();
    }
    let reopened = Database::open(temporary.path()).unwrap();
    let statuses = reopened
        .lock()
        .unwrap()
        .prepare("SELECT status FROM axfr_attempts ORDER BY nameserver")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(statuses, vec!["empty", "protocol_error"]);
}

#[test]
fn numeric_passive_pagination_is_additive_atomic_and_resume_safe() {
    let db = Database::in_memory().unwrap();
    let query_hash = domain_hash("viewdns:pages:v1:example.com:output=json");
    let page_one_hash = domain_hash("api.example.com\0mail.example.com");
    let page_one = PassivePaginationPage {
        position: 1,
        next_position: 2,
        records_seen: 2,
        expected_records: Some(3),
        expected_pages: Some(2),
        page_hash: page_one_hash.clone(),
        page_records: 2,
    };
    let first_names = BTreeSet::from(["api.example.com".to_owned(), "mail.example.com".to_owned()]);
    db.commit_passive_pagination_page(
        "example.com",
        "viewdns",
        "pages",
        1,
        &query_hash,
        &page_one,
        &first_names,
    )
    .unwrap();

    let state = db
        .passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
        .unwrap()
        .unwrap();
    assert_eq!(state.next_position, 2);
    assert_eq!(state.records_seen, 2);
    assert_eq!(state.last_page_records, 2);
    assert_eq!(state.last_page_hash, page_one_hash);

    // A resumed connector deliberately overlaps the last complete page.
    // The cumulative counter remains stable instead of double-counting it.
    db.commit_passive_pagination_page(
        "example.com",
        "viewdns",
        "pages",
        1,
        &query_hash,
        &page_one,
        &first_names,
    )
    .unwrap();
    assert_eq!(
        db.passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
            .unwrap()
            .unwrap()
            .records_seen,
        2
    );
    let overlap_times_seen: i64 = db
        .lock()
        .unwrap()
        .query_row(
            r#"SELECT evidence.times_seen
                   FROM observation_evidence evidence
                   JOIN observed_names names ON names.id=evidence.name_id
                   WHERE evidence.root_domain='example.com'
                     AND evidence.source='passive:viewdns'
                     AND names.fqdn='api.example.com'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(overlap_times_seen, 1, "overlap must be idempotent");
    assert!(
        db.finish_passive_pagination("example.com", "viewdns", "pages", 1, &query_hash)
            .is_err(),
        "a lane cannot finish before its advertised records and pages are complete"
    );

    db.lock()
        .unwrap()
        .execute_batch(
            r#"CREATE TRIGGER fail_passive_page_advance
                   BEFORE UPDATE ON passive_pagination_state
                   WHEN NEW.next_position=3
                   BEGIN SELECT RAISE(ABORT, 'forced pagination failure'); END;"#,
        )
        .unwrap();
    let page_two = PassivePaginationPage {
        position: 2,
        next_position: 3,
        records_seen: 3,
        expected_records: Some(3),
        expected_pages: Some(2),
        page_hash: domain_hash("www.example.com"),
        page_records: 1,
    };
    assert!(
        db.commit_passive_pagination_page(
            "example.com",
            "viewdns",
            "pages",
            1,
            &query_hash,
            &page_two,
            &BTreeSet::from(["www.example.com".to_owned()]),
        )
        .is_err()
    );
    assert_eq!(
        db.passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
            .unwrap()
            .unwrap()
            .next_position,
        2,
        "a failed SQLite transaction must not advance the page"
    );
    assert!(
        db.observation_names("example.com", "passive:viewdns")
            .unwrap()
            .iter()
            .all(|name| name != "www.example.com"),
        "the page evidence must roll back with its progress row"
    );

    db.lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_passive_page_advance")
        .unwrap();
    db.commit_passive_pagination_page(
        "example.com",
        "viewdns",
        "pages",
        1,
        &query_hash,
        &page_two,
        &BTreeSet::from(["www.example.com".to_owned()]),
    )
    .unwrap();
    db.finish_passive_pagination("example.com", "viewdns", "pages", 1, &query_hash)
        .unwrap();
    assert!(
        db.passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
            .unwrap()
            .is_some_and(|state| state.done),
        "lane completion must remain durable until source publication"
    );
    assert!(
        db.passive_cache("example.com", "viewdns")
            .unwrap()
            .is_some_and(|cache| cache.updated_at == 0),
        "finishing one lane must not publish source freshness"
    );
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='viewdns'
                         AND active=1"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
        "lane completion must retain replay markers until source completion"
    );
    db.complete_passive_pagination_source(
        "example.com",
        "viewdns",
        &[("pages", 1, query_hash.as_str())],
    )
    .unwrap();
    assert!(
        db.passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
            .unwrap()
            .is_none()
    );
    assert!(
        db.passive_cache("example.com", "viewdns")
            .unwrap()
            .is_some_and(|cache| cache.updated_at > 0),
        "source completion must publish cache freshness atomically"
    );
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='viewdns'
                         AND active=1"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "source completion must close the replay generation atomically"
    );
    assert_eq!(
        db.observation_names("example.com", "passive:viewdns")
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "api.example.com".to_owned(),
            "mail.example.com".to_owned(),
            "www.example.com".to_owned(),
        ])
    );
}

#[test]
fn passive_source_completion_requires_every_expected_lane_atomically() {
    let db = Database::in_memory().unwrap();
    let lane_a_hash = domain_hash("fixture:lane-a:v1:example.com");
    let lane_b_hash = domain_hash("fixture:lane-b:v1:example.com");
    let expected = [
        ("lane_a", 1, lane_a_hash.as_str()),
        ("lane_b", 1, lane_b_hash.as_str()),
    ];
    db.prepare_passive_pagination_source("example.com", "fixture", &expected)
        .unwrap();
    let page = |name: &str| PassivePaginationPage {
        position: 1,
        next_position: 2,
        records_seen: 1,
        expected_records: Some(1),
        expected_pages: Some(1),
        page_hash: domain_hash(name),
        page_records: 1,
    };

    db.commit_passive_pagination_page(
        "example.com",
        "fixture",
        "lane_a",
        1,
        &lane_a_hash,
        &page("api.example.com"),
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();
    db.finish_passive_pagination("example.com", "fixture", "lane_a", 1, &lane_a_hash)
        .unwrap();

    assert!(
        db.complete_passive_pagination_source("example.com", "fixture", &expected)
            .is_err(),
        "a missing lane must fail closed"
    );
    assert!(
        db.passive_cache("example.com", "fixture")
            .unwrap()
            .is_some_and(|cache| cache.updated_at == 0),
        "an incomplete lane set must never publish freshness"
    );
    assert!(
        db.passive_pagination_resume("example.com", "fixture", "lane_a", 1, &lane_a_hash,)
            .unwrap()
            .is_some_and(|state| state.done),
        "a completed lane must survive the failed source completion"
    );

    db.commit_passive_pagination_page(
        "example.com",
        "fixture",
        "lane_b",
        1,
        &lane_b_hash,
        &page("www.example.com"),
        &BTreeSet::from(["www.example.com".to_owned()]),
    )
    .unwrap();
    db.finish_passive_pagination("example.com", "fixture", "lane_b", 1, &lane_b_hash)
        .unwrap();
    db.complete_passive_pagination_source("example.com", "fixture", &expected)
        .unwrap();

    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM passive_pagination_state
                       WHERE root_domain='example.com' AND source='fixture'"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='fixture'
                         AND active=1"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    drop(connection);
    assert!(
        db.passive_cache("example.com", "fixture")
            .unwrap()
            .is_some_and(|cache| cache.updated_at > 0)
    );
    assert!(
        db.complete_passive_pagination_source("example.com", "fixture", &expected)
            .is_err(),
        "a concurrent duplicate completion must fail closed"
    );
}

#[test]
fn passive_pagination_preparation_prunes_only_obsolete_lane_contracts() {
    let db = Database::in_memory().unwrap();
    let old_hash = domain_hash("fixture:retired:v1:example.com");
    let current_hash = domain_hash("fixture:current:v1:example.com");
    let page = PassivePaginationPage {
        position: 1,
        next_position: 2,
        records_seen: 1,
        expected_records: Some(2),
        expected_pages: Some(2),
        page_hash: domain_hash("api.example.com"),
        page_records: 1,
    };
    db.commit_passive_pagination_page(
        "example.com",
        "fixture",
        "retired",
        1,
        &old_hash,
        &page,
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();
    db.commit_passive_pagination_page(
        "example.com",
        "fixture",
        "current",
        1,
        &current_hash,
        &page,
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();

    db.prepare_passive_pagination_source(
        "example.com",
        "fixture",
        &[("current", 1, current_hash.as_str())],
    )
    .unwrap();
    assert!(
        db.passive_pagination_resume("example.com", "fixture", "retired", 1, &old_hash,)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.passive_pagination_resume("example.com", "fixture", "current", 1, &current_hash,)
            .unwrap()
            .unwrap()
            .next_position,
        2
    );
    assert_eq!(
        db.observation_names("example.com", "passive:fixture")
            .unwrap(),
        vec!["api.example.com"],
        "contract cleanup must not delete permanent observations"
    );
}

#[test]
fn passive_pagination_contract_change_restarts_without_deleting_observations() {
    let db = Database::in_memory().unwrap();
    let old_hash = domain_hash("viewdns:pages:v1:example.com:output=json");
    db.commit_passive_pagination_page(
        "example.com",
        "viewdns",
        "pages",
        1,
        &old_hash,
        &PassivePaginationPage {
            position: 1,
            next_position: 2,
            records_seen: 1,
            expected_records: Some(2),
            expected_pages: Some(2),
            page_hash: domain_hash("api.example.com"),
            page_records: 1,
        },
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();
    let new_hash = domain_hash("viewdns:pages:v2:example.com:output=json");
    assert!(
        db.passive_pagination_resume("example.com", "viewdns", "pages", 2, &new_hash)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.observation_names("example.com", "passive:viewdns")
            .unwrap(),
        vec!["api.example.com"]
    );
    let (version, opaque_columns): (i64, i64) = db
        .lock()
        .unwrap()
        .query_row(
            r#"SELECT (SELECT user_version FROM pragma_user_version),
                          (SELECT COUNT(*) FROM pragma_table_info('passive_pagination_state')
                           WHERE lower(name) LIKE '%cursor%'
                              OR lower(name) LIKE '%token%'
                              OR lower(name) LIKE '%url%')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(version, 9, "the additive table must not bump user_version");
    assert_eq!(opaque_columns, 0, "opaque pagination state is forbidden");
}

#[test]
fn permanent_knowledge_keeps_words_patterns_and_passive_results() {
    let db = Database::in_memory().unwrap();
    let attempted = BTreeSet::from(["api".to_owned(), "dev".to_owned()]);
    let successful = BTreeSet::from(["api".to_owned()]);
    db.record_word_results("example.com", &attempted, &successful)
        .unwrap();
    db.record_patterns("example.com", &BTreeSet::from(["api.dev".to_owned()]))
        .unwrap();
    db.store_passive_cache("example.com", "crtsh", &["deep.api.example.com".to_owned()])
        .unwrap();
    db.store_passive_cache("example.com", "crtsh", &[]).unwrap();
    db.store_passive_cache("example.com", "crtsh", &["www.example.com".to_owned()])
        .unwrap();
    db.lock()
        .unwrap()
        .execute(
            r#"UPDATE passive_cache SET updated_at=42
                   WHERE root_domain='example.com' AND source='crtsh'"#,
            [],
        )
        .unwrap();
    db.store_partial_passive_cache("example.com", "crtsh", &["partial.example.com".to_owned()])
        .unwrap();
    db.store_partial_passive_cache(
        "example.com",
        "page-only",
        &["first-page.example.com".to_owned()],
    )
    .unwrap();

    assert_eq!(db.ranked_words(1).unwrap(), vec!["api"]);
    assert_eq!(db.ranked_patterns(1).unwrap(), vec!["api.dev"]);
    assert_eq!(
        db.passive_cache("example.com", "crtsh")
            .unwrap()
            .unwrap()
            .names,
        vec![
            "deep.api.example.com",
            "partial.example.com",
            "www.example.com"
        ]
    );
    assert_eq!(
        db.passive_cache("example.com", "crtsh")
            .unwrap()
            .unwrap()
            .updated_at,
        42
    );
    let page_only = db
        .passive_cache("example.com", "page-only")
        .unwrap()
        .unwrap();
    assert_eq!(page_only.updated_at, 0);
    assert_eq!(page_only.names, vec!["first-page.example.com"]);
}

#[test]
fn passive_cache_bounded_limits_reads_without_discarding_observations() {
    let db = Database::in_memory().unwrap();
    let full_page = BTreeSet::from([
        "a.example.com".to_owned(),
        "b.example.com".to_owned(),
        "c.example.com".to_owned(),
        "d.example.com".to_owned(),
    ]);
    db.store_passive_observation_page("example.com", "fixture", &full_page)
        .unwrap();

    let bounded = db
        .passive_cache_bounded("example.com", "fixture", 2)
        .unwrap()
        .unwrap();
    assert_eq!(bounded.names, vec!["a.example.com", "b.example.com"]);
    assert_eq!(bounded.updated_at, 0);
    assert!(
        db.passive_cache_bounded("example.com", "fixture", 0)
            .unwrap()
            .unwrap()
            .names
            .is_empty()
    );
    assert_eq!(
        db.passive_cache("example.com", "fixture")
            .unwrap()
            .unwrap()
            .names,
        full_page.into_iter().collect::<Vec<_>>()
    );
}

#[test]
fn passive_page_novelty_counts_durable_names_outside_any_working_set() {
    let db = Database::in_memory().unwrap();
    let already_known = (0..100)
        .map(|index| format!("known-{index:03}.example.com"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        db.store_passive_observation_page("example.com", "prior", &already_known)
            .unwrap(),
        already_known.len()
    );
    let mut large_page = already_known;
    large_page.extend(
        (0..500)
            .map(|index| format!("zz-new-{index:03}.example.com"))
            .collect::<BTreeSet<_>>(),
    );
    // A scanner working set capped to the lexicographically first 100
    // names would retain only the old entries. The durable page commit
    // still reports every globally new name for source learning.
    assert_eq!(
        db.store_passive_observation_page("example.com", "large", &large_page)
            .unwrap(),
        500
    );
    assert_eq!(
        db.store_passive_observation_page("example.com", "large", &large_page)
            .unwrap(),
        0,
        "replaying a page must not manufacture novelty"
    );
    assert_eq!(
        db.passive_cache_bounded("example.com", "large", 100)
            .unwrap()
            .unwrap()
            .names
            .len(),
        100
    );
    assert_eq!(
        db.passive_cache("example.com", "large")
            .unwrap()
            .unwrap()
            .names
            .len(),
        600
    );
}

#[test]
fn passive_refresh_replay_is_idempotent_across_database_reopen() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let page = BTreeSet::from(["api.example.com".to_owned(), "mail.example.com".to_owned()]);
    {
        let db = Database::open(temporary.path()).unwrap();
        assert_eq!(
            db.store_passive_observation_page("example.com", "fixture", &page)
                .unwrap(),
            2
        );
        db.mark_passive_cache_refresh("example.com", "fixture", false)
            .unwrap();
    }

    {
        let db = Database::open(temporary.path()).unwrap();
        assert_eq!(
            db.store_passive_observation_page("example.com", "fixture", &page)
                .unwrap(),
            0
        );
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT MIN(evidence.times_seen)
                           FROM observation_evidence evidence
                           WHERE evidence.root_domain='example.com'
                             AND evidence.source='passive:fixture'"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "an unfinished refresh replay must not inflate evidence"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM passive_refresh_seen", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "generation ids replace per-name replay marker rows"
        );
        drop(connection);
        db.mark_passive_cache_refresh("example.com", "fixture", true)
            .unwrap();
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM passive_refresh_sessions WHERE active=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM passive_refresh_seen", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    let db = Database::open(temporary.path()).unwrap();
    db.store_passive_observation_page("example.com", "fixture", &page)
        .unwrap();
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                r#"SELECT MIN(evidence.times_seen)
                       FROM observation_evidence evidence
                       WHERE evidence.root_domain='example.com'
                         AND evidence.source='passive:fixture'"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2,
        "a new generation after successful completion is a new observation"
    );
}

#[test]
fn passive_refresh_sessions_are_isolated_by_domain_and_source() {
    let db = Database::in_memory().unwrap();
    let page = BTreeSet::from(["shared.example.com".to_owned()]);
    db.store_passive_observation_page("example.com", "alpha", &page)
        .unwrap();
    db.store_passive_observation_page("example.com", "alpha", &page)
        .unwrap();
    db.store_passive_observation_page("example.com", "beta", &page)
        .unwrap();
    db.store_passive_observation_page("example.net", "alpha", &page)
        .unwrap();

    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM passive_refresh_sessions WHERE active=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        3
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT MAX(times_seen) FROM observation_evidence",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(connection);

    db.mark_passive_cache_refresh("example.com", "alpha", true)
        .unwrap();
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM passive_refresh_sessions WHERE active=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE active=1 AND (
                           (root_domain='example.com' AND source='beta')
                           OR (root_domain='example.net' AND source='alpha')
                       )"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
}

#[test]
fn passive_refresh_lease_is_exclusive_and_owner_safe() {
    let db = Database::in_memory().unwrap();
    let owner_a = domain_hash("lease-owner-a");
    let owner_b = domain_hash("lease-owner-b");
    let ttl = Duration::from_secs(30);

    assert!(
        db.try_acquire_passive_refresh_lease("example.com", "fixture", &owner_a, ttl)
            .unwrap()
    );
    assert!(
        !db.try_acquire_passive_refresh_lease("example.com", "fixture", &owner_b, ttl)
            .unwrap(),
        "a concurrent owner must be deferred"
    );
    assert!(
        db.renew_passive_refresh_lease("example.com", "fixture", &owner_a, ttl)
            .unwrap()
    );
    assert!(
        !db.renew_passive_refresh_lease("example.com", "fixture", &owner_b, ttl)
            .unwrap()
    );
    assert!(
        !db.release_passive_refresh_lease("example.com", "fixture", &owner_b)
            .unwrap(),
        "a stale guard cannot release another owner's lease"
    );
    assert!(
        db.release_passive_refresh_lease("example.com", "fixture", &owner_a)
            .unwrap()
    );
    assert!(
        db.try_acquire_passive_refresh_lease("example.com", "fixture", &owner_b, ttl)
            .unwrap()
    );

    db.lock()
        .unwrap()
        .execute(
            r#"UPDATE passive_refresh_leases SET expires_at=?1
                   WHERE root_domain='example.com' AND source='fixture'"#,
            [now_epoch().saturating_sub(1)],
        )
        .unwrap();
    assert!(
        db.try_acquire_passive_refresh_lease("example.com", "fixture", &owner_a, ttl)
            .unwrap(),
        "an expired owner must not block a bounded takeover"
    );
    assert!(
        !db.release_passive_refresh_lease("example.com", "fixture", &owner_b)
            .unwrap()
    );
    assert!(
        db.release_passive_refresh_lease("example.com", "fixture", &owner_a)
            .unwrap()
    );
}

#[test]
fn passive_page_failure_rolls_back_observations_and_restart_markers() {
    let db = Database::in_memory().unwrap();
    db.lock()
        .unwrap()
        .execute_batch(
            r#"CREATE TRIGGER fail_passive_cache_marker
                   BEFORE INSERT ON passive_cache
                   BEGIN SELECT RAISE(ABORT, 'forced cache marker failure'); END;"#,
        )
        .unwrap();
    assert!(
        db.store_passive_observation_page(
            "example.com",
            "fixture",
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .is_err()
    );
    let connection = db.lock().unwrap();
    for table in [
        "observed_names",
        "observation_evidence",
        "passive_refresh_sessions",
        "passive_refresh_seen",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must roll back with the failed page");
    }
}

#[test]
fn abandoned_refresh_cleanup_keeps_permanent_observations() {
    let db = Database::in_memory().unwrap();
    db.store_passive_observation_page(
        "example.com",
        "abandoned",
        &BTreeSet::from(["old.example.com".to_owned()]),
    )
    .unwrap();
    db.lock()
        .unwrap()
        .execute(
            r#"UPDATE passive_refresh_sessions
                   SET updated_at=?1
                   WHERE root_domain='example.com' AND source='abandoned'"#,
            [now_epoch()
                .saturating_sub(PASSIVE_REFRESH_ABANDONED_AFTER_SECS)
                .saturating_sub(1)],
        )
        .unwrap();

    db.store_passive_observation_page(
        "example.net",
        "current",
        &BTreeSet::from(["new.example.net".to_owned()]),
    )
    .unwrap();
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='abandoned'
                         AND active=1"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*)
                       FROM observation_evidence evidence
                       JOIN observed_names names ON names.id=evidence.name_id
                       WHERE evidence.root_domain='example.com'
                         AND evidence.source='passive:abandoned'
                         AND names.fqdn='old.example.com'"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
        "cleanup may remove restart metadata but never observations"
    );
}

#[test]
fn abandoned_numeric_refresh_restarts_without_deleting_observations() {
    let db = Database::in_memory().unwrap();
    let query_hash = domain_hash("fixture:pages:v1:example.com");
    db.commit_passive_pagination_page(
        "example.com",
        "fixture",
        "pages",
        1,
        &query_hash,
        &PassivePaginationPage {
            position: 1,
            next_position: 2,
            records_seen: 1,
            expected_records: Some(2),
            expected_pages: Some(2),
            page_hash: domain_hash("api.example.com"),
            page_records: 1,
        },
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();
    db.lock()
        .unwrap()
        .execute(
            r#"UPDATE passive_refresh_sessions
                   SET updated_at=?1
                   WHERE root_domain='example.com' AND source='fixture'"#,
            [now_epoch()
                .saturating_sub(PASSIVE_REFRESH_ABANDONED_AFTER_SECS)
                .saturating_sub(1)],
        )
        .unwrap();

    db.store_passive_observation_page(
        "example.net",
        "current",
        &BTreeSet::from(["new.example.net".to_owned()]),
    )
    .unwrap();
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='fixture'
                         AND active=1"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "an abandoned generation must be closed"
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM passive_pagination_state
                       WHERE root_domain='example.com' AND source='fixture'"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "an abandoned numeric lane must restart at page one"
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM observation_evidence
                       WHERE root_domain='example.com'
                         AND source='passive:fixture'"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
        "cleanup must retain permanent observations"
    );
}

#[test]
fn tls_cache_does_not_attribute_old_sans_to_a_rotated_certificate() {
    let db = Database::in_memory().unwrap();
    db.store_tls_cache(
        "example.com",
        "www.example.com",
        443,
        "old-fingerprint",
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();
    db.store_tls_cache(
        "example.com",
        "www.example.com",
        443,
        "new-fingerprint",
        &BTreeSet::from(["admin.example.com".to_owned()]),
    )
    .unwrap();

    let cached = db
        .tls_cache("example.com", "www.example.com", 443)
        .unwrap()
        .unwrap();
    assert_eq!(cached.fingerprint_sha256, "new-fingerprint");
    assert_eq!(cached.names, vec!["admin.example.com"]);
    assert_eq!(
        db.observation_names("example.com", "tls:www.example.com:443")
            .unwrap(),
        vec!["admin.example.com", "api.example.com"]
    );
}

#[test]
fn tls_cache_replaces_even_repeated_observations_of_the_same_certificate() {
    let db = Database::in_memory().unwrap();
    db.store_tls_cache(
        "example.com",
        "www.example.com",
        443,
        "same-fingerprint",
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();
    db.store_tls_cache(
        "example.com",
        "www.example.com",
        443,
        "same-fingerprint",
        &BTreeSet::from(["admin.example.com".to_owned()]),
    )
    .unwrap();

    assert_eq!(
        db.tls_cache("example.com", "www.example.com", 443)
            .unwrap()
            .unwrap()
            .names,
        vec!["admin.example.com"]
    );
}

#[test]
fn discovery_graph_is_persistent_and_counts_repeated_evidence() {
    let db = Database::in_memory().unwrap();
    let edges = BTreeSet::from([DiscoveryEdge {
        owner: "example.com".to_owned(),
        record_type: "MX".to_owned(),
        value: "10 mail.example.com".to_owned(),
        target: Some("mail.example.com".to_owned()),
    }]);
    let services = BTreeSet::from([ServiceEndpoint {
        hostname: "mail.example.com".to_owned(),
        port: 25,
        transport: "smtp-starttls".to_owned(),
        source: "dns-mx:example.com".to_owned(),
    }]);
    let zones = BTreeSet::from(["prod.example.com".to_owned()]);
    db.store_discovery_graph("example.com", &edges, &services, &zones)
        .unwrap();
    db.store_discovery_graph("example.com", &edges, &services, &zones)
        .unwrap();

    let connection = db.lock().unwrap();
    let times_seen = connection
        .query_row("SELECT times_seen FROM discovery_edges", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    assert_eq!(times_seen, 2);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM service_endpoints", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM child_zones", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
}

#[test]
fn web_cache_tracks_the_current_snapshot_while_history_is_permanent() {
    let db = Database::in_memory().unwrap();
    db.store_web_cache(
        "example.com",
        "https://www.example.com/",
        200,
        &BTreeSet::from(["api.example.com".to_owned()]),
        &["https://www.example.com/old.js".to_owned()],
        &WebCacheMetadata {
            etag: Some("etag-1".to_owned()),
            last_modified: None,
            content_hash: Some("hash-1".to_owned()),
        },
    )
    .unwrap();
    db.store_web_cache(
        "example.com",
        "https://www.example.com/",
        200,
        &BTreeSet::from(["static.example.com".to_owned()]),
        &["https://www.example.com/current.js".to_owned()],
        &WebCacheMetadata {
            etag: Some("etag-2".to_owned()),
            last_modified: None,
            content_hash: Some("hash-2".to_owned()),
        },
    )
    .unwrap();
    let web = db
        .web_cache("example.com", "https://www.example.com/")
        .unwrap()
        .unwrap();
    assert_eq!(web.status, 200);
    assert_eq!(web.names, vec!["static.example.com"]);
    assert_eq!(web.assets, vec!["https://www.example.com/current.js"]);
    assert_eq!(
        db.observation_names("example.com", "web:https://www.example.com/")
            .unwrap(),
        vec!["api.example.com", "static.example.com"]
    );

    // DNSSEC walk results remain an intentionally cumulative discovery corpus.
    db.store_dnssec_cache(
        "example.com",
        "example.com",
        "ns1.example.com",
        "partial",
        &BTreeSet::from(["a.example.com".to_owned()]),
    )
    .unwrap();
    db.store_dnssec_cache(
        "example.com",
        "example.com",
        "ns2.example.com",
        "walked",
        &BTreeSet::from(["b.example.com".to_owned()]),
    )
    .unwrap();
    let dnssec = db
        .dnssec_cache("example.com", "example.com")
        .unwrap()
        .unwrap();
    assert_eq!(dnssec.status, "walked");
    assert_eq!(dnssec.names, vec!["a.example.com", "b.example.com"]);
}

#[test]
fn generator_context_and_ct_cursor_are_persistent() {
    let db = Database::in_memory().unwrap();
    db.store_discovery_graph(
        "example.com",
        &BTreeSet::from([DiscoveryEdge {
            owner: "example.com".to_owned(),
            record_type: "NS".to_owned(),
            value: "alice.ns.cloudflare.com".to_owned(),
            target: None,
        }]),
        &BTreeSet::new(),
        &BTreeSet::new(),
    )
    .unwrap();
    let attempts = HashMap::from([("environment-swap".to_owned(), 5_usize)]);
    let successes = HashMap::from([("environment-swap".to_owned(), 2_usize)]);
    db.record_generator_results("example.com", &attempts, &successes)
        .unwrap();
    db.record_generator_results("another.com", &attempts, &successes)
        .unwrap();
    let score = db
        .generator_scores("third.com")
        .unwrap()
        .get("environment-swap")
        .copied()
        .unwrap_or_default();
    assert!(score > 0);
    let provider_bandit = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM generator_bandits WHERE context='provider:cloudflare'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(provider_bandit, 1);

    db.store_ct_global_batch(
        "https://ct.example/",
        42,
        &BTreeSet::from([
            "api.example.com".to_owned(),
            "deep.api.example.com".to_owned(),
            "api.notexample.com".to_owned(),
            "www.example.net".to_owned(),
        ]),
    )
    .unwrap();
    assert_eq!(
        db.ct_global_cursor("https://ct.example/").unwrap(),
        Some(42)
    );
    db.store_ct_global_batch("https://ct.example/", 12, &BTreeSet::new())
        .unwrap();
    assert_eq!(
        db.ct_global_cursor("https://ct.example/").unwrap(),
        Some(42)
    );
    assert_eq!(
        db.ct_global_states()
            .unwrap()
            .get("https://ct.example/")
            .map(|(cursor, _)| *cursor),
        Some(42)
    );
    db.reset_ct_global_cursor("https://ct.example/", 5).unwrap();
    assert_eq!(db.ct_global_cursor("https://ct.example/").unwrap(), Some(5));
    assert_eq!(
        db.ct_names_for_domain("example.com", 10).unwrap(),
        vec!["api.example.com", "deep.api.example.com"]
    );
    let connection = db.lock().unwrap();
    let mut statement = connection
        .prepare(
            r#"EXPLAIN QUERY PLAN SELECT fqdn FROM ct_names
                   WHERE reversed_name>=?1 AND reversed_name<?2
                   ORDER BY last_seen DESC, fqdn ASC LIMIT ?3"#,
        )
        .unwrap();
    let plan = statement
        .query_map(params!["com.example.", "com.example/", 10_i64], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|detail| detail.contains("idx_ct_names_reversed"))
    );
}

#[test]
fn scheduler_ranking_is_cost_aware_deterministic_and_bounded() {
    let db = Database::in_memory().unwrap();
    db.record_scheduler_outcomes(
        "example.com",
        &[
            SchedulerOutcome {
                generator: "cheap".to_owned(),
                attempts: 100,
                exclusive_live: 20,
                packets: 120,
                total_cost: 50.0,
            },
            SchedulerOutcome {
                generator: "expensive".to_owned(),
                attempts: 100,
                exclusive_live: 20,
                packets: 120,
                total_cost: 200.0,
            },
        ],
    )
    .unwrap();
    let rankings = db
        .scheduler_rankings(
            "example.com",
            &["cheap".to_owned(), "expensive".to_owned()],
            10,
        )
        .unwrap();
    assert_eq!(rankings.len(), 2);
    assert_eq!(rankings[0].generator, "cheap");
    assert!(rankings[0].priority_milli > rankings[1].priority_milli);
    assert!((rankings[0].average_cost - 0.5).abs() < f64::EPSILON);
    assert!((rankings[1].average_cost - 2.0).abs() < f64::EPSILON);
    assert_eq!(rankings[0].exclusive_live, 20);
    assert_eq!(rankings[0].packets, 120);

    let global = db
        .lock()
        .unwrap()
        .query_row(
            r#"SELECT alpha, beta, packets, exclusive_rewards, total_cost
                   FROM scheduler_arms WHERE context='global' AND generator='cheap'"#,
            [],
            |row| {
                Ok((
                    row.get::<_, f64>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, f64>(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(global, (21.0, 81.0, 120, 20, 50.0));

    let invalid = SchedulerOutcome {
        generator: "invalid".to_owned(),
        attempts: 1,
        exclusive_live: 2,
        packets: 1,
        total_cost: 1.0,
    };
    assert!(
        db.record_scheduler_outcomes("example.com", &[invalid])
            .is_err()
    );
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM scheduler_arms WHERE generator='invalid'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );

    let too_many_generators = (0..=MAX_SCHEDULER_GENERATORS)
        .map(|index| format!("generator-{index}"))
        .collect::<Vec<_>>();
    assert!(
        db.scheduler_rankings("example.com", &too_many_generators, usize::MAX)
            .is_err()
    );
    let too_many_outcomes = vec![
        SchedulerOutcome {
            generator: "bounded".to_owned(),
            attempts: 1,
            exclusive_live: 0,
            packets: 1,
            total_cost: 1.0,
        };
        MAX_SCHEDULER_OUTCOMES + 1
    ];
    assert!(
        db.record_scheduler_outcomes("example.com", &too_many_outcomes)
            .is_err()
    );
}

#[test]
fn generator_scores_consume_cost_aware_scheduler_arms() {
    let db = Database::in_memory().unwrap();
    db.record_scheduler_outcomes(
        "example.com",
        &[
            SchedulerOutcome {
                generator: "number-neighbor".to_owned(),
                attempts: 50,
                exclusive_live: 10,
                packets: 50,
                total_cost: 25.0,
            },
            SchedulerOutcome {
                generator: "token-order".to_owned(),
                attempts: 50,
                exclusive_live: 10,
                packets: 50,
                total_cost: 200.0,
            },
        ],
    )
    .unwrap();

    let scores = db.generator_scores("example.com").unwrap();
    assert!(scores["number-neighbor"] > scores["token-order"]);
}

#[test]
fn discovery_actions_claim_yield_per_cost_and_complete_exactly_once() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let actions = [
        DiscoveryActionInput {
            fqdn: Some("a.example.com".to_owned()),
            zone: "example.com".to_owned(),
            kind: "dns".to_owned(),
            generator: "generator-a".to_owned(),
            context_key: "suffix:com".to_owned(),
            priority_class: 0,
            predicted_unique_live: 0.8,
            predicted_cost: 2.0,
        },
        DiscoveryActionInput {
            fqdn: Some("b.example.com".to_owned()),
            zone: "example.com".to_owned(),
            kind: "dns".to_owned(),
            generator: "generator-b".to_owned(),
            context_key: "suffix:com".to_owned(),
            priority_class: 0,
            predicted_unique_live: 0.5,
            predicted_cost: 0.5,
        },
        DiscoveryActionInput {
            fqdn: Some("c.example.com".to_owned()),
            zone: "example.com".to_owned(),
            kind: "dns".to_owned(),
            generator: "generator-c".to_owned(),
            context_key: "suffix:com".to_owned(),
            priority_class: 1,
            predicted_unique_live: 10.0,
            predicted_cost: 0.01,
        },
    ];
    assert_eq!(db.enqueue_discovery_actions(scan_id, &actions).unwrap(), 3);
    let claimed = db.claim_discovery_actions(scan_id, 2).unwrap();
    assert_eq!(
        claimed
            .iter()
            .map(|action| action.generator.as_str())
            .collect::<Vec<_>>(),
        vec!["generator-b", "generator-a"]
    );
    let outcome = SchedulerOutcome {
        generator: "generator-b".to_owned(),
        attempts: 1,
        exclusive_live: 1,
        packets: 2,
        total_cost: 0.5,
    };
    assert!(
        db.complete_discovery_action(claimed[0].id, &outcome, &json!({"rcode": "NOERROR"}))
            .unwrap()
    );
    assert!(
        !db.complete_discovery_action(claimed[0].id, &outcome, &json!({}))
            .unwrap()
    );
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                r#"SELECT COUNT(*) FROM scheduler_arms
                       WHERE generator='generator-b' AND context IN ('global', 'suffix:com')
                         AND alpha=2.0 AND beta=1.0
                         AND exclusive_rewards=1 AND total_cost=0.5"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
}

#[test]
fn legacy_bandit_is_migrated_to_scheduler_once() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    {
        let db = Database::open(temporary.path()).unwrap();
        let connection = db.lock().unwrap();
        connection
            .execute("DELETE FROM scheduler_arms", [])
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO generator_bandits(
                           context, generator, alpha, beta, pulls, rewards, last_seen
                       ) VALUES ('global', 'legacy', 4.0, 7.0, 9, 3, 123)"#,
                [],
            )
            .unwrap();
    }
    for _ in 0..2 {
        let db = Database::open(temporary.path()).unwrap();
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    r#"SELECT alpha, beta, packets, exclusive_rewards, total_cost
                           FROM scheduler_arms
                           WHERE context='global' AND generator='legacy'"#,
                    [],
                    |row| {
                        Ok((
                            row.get::<_, f64>(0)?,
                            row.get::<_, f64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, f64>(4)?,
                        ))
                    },
                )
                .unwrap(),
            (4.0, 7.0, 9, 0, 9.0)
        );
    }
}

#[test]
fn static_ct_tiles_names_and_cursor_commit_atomically_and_are_reusable() {
    let db = Database::in_memory().unwrap();
    let log_url = "https://ct.example/2026h2/";
    db.store_ct_global_batch(log_url, 900, &BTreeSet::new())
        .unwrap();
    let payload = b"immutable-static-ct-tile".to_vec();
    let content_hash = format!("{:x}", Sha256::digest(&payload));
    let batch = crate::ct_static::StaticCtBatch {
        checkpoint_origin: "ct.example/2026h2".to_owned(),
        checkpoint_size: 512,
        checkpoint_hash: "checkpoint-a".to_owned(),
        reset_cursor: true,
        next_cursor: 257,
        entries_processed: 1,
        names: BTreeSet::from(["api.example.com".to_owned()]),
        tiles: vec![crate::ct_static::StaticTile {
            path: "tile/data/001".to_owned(),
            checkpoint_size: 512,
            checkpoint_hash: "checkpoint-a".to_owned(),
            content_hash: content_hash.clone(),
            payload: payload.clone(),
        }],
        ..crate::ct_static::StaticCtBatch::default()
    };

    db.store_ct_static_batch(log_url, &batch).unwrap();

    assert_eq!(db.ct_global_cursor(log_url).unwrap(), Some(257));
    assert_eq!(
        db.ct_names_for_domain("example.com", 10).unwrap(),
        vec!["api.example.com"]
    );
    assert_eq!(
        db.ct_static_tile(log_url, "tile/data/001", 512, "checkpoint-a")
            .unwrap(),
        Some((content_hash, payload))
    );
    assert!(
        db.ct_static_tile(log_url, "tile/data/001", 513, "checkpoint-a")
            .unwrap()
            .is_none()
    );
    assert!(
        db.ct_static_tile(log_url, "tile/data/001", 512, "checkpoint-b")
            .unwrap()
            .is_none()
    );
}

#[test]
fn existing_v9_ct_tile_table_is_repaired_without_losing_payloads() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    {
        let db = Database::open(temporary.path()).unwrap();
        let connection = db.lock().unwrap();
        connection.execute("DROP TABLE ct_tiles", []).unwrap();
        connection
            .execute_batch(
                r#"CREATE TABLE ct_tiles (
                           log_url TEXT NOT NULL,
                           tile_path TEXT NOT NULL,
                           checkpoint_size INTEGER NOT NULL,
                           content_hash TEXT NOT NULL,
                           payload BLOB NOT NULL,
                           verified INTEGER NOT NULL DEFAULT 0,
                           updated_at INTEGER NOT NULL,
                           PRIMARY KEY(log_url, tile_path)
                       ) WITHOUT ROWID;
                       INSERT INTO ct_tiles(
                           log_url, tile_path, checkpoint_size, content_hash,
                           payload, verified, updated_at
                       ) VALUES (
                           'https://ct.example/2026h2/', 'tile/data/000', 256,
                           'legacy-hash', X'010203', 0, 1
                       );
                       PRAGMA user_version=9;"#,
            )
            .unwrap();
    }

    let reopened = Database::open(temporary.path()).unwrap();
    let connection = reopened.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                r#"SELECT checkpoint_hash, content_hash, payload
                       FROM ct_tiles WHERE tile_path='tile/data/000'"#,
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .unwrap(),
        ("".to_owned(), "legacy-hash".to_owned(), vec![1, 2, 3])
    );
}

#[test]
fn conflicting_static_ct_tile_rolls_back_names_and_cursor() {
    let db = Database::in_memory().unwrap();
    let log_url = "https://ct.example/2026h2/";
    let first_payload = b"first immutable payload".to_vec();
    let first = crate::ct_static::StaticCtBatch {
        checkpoint_origin: "ct.example/2026h2".to_owned(),
        checkpoint_size: 512,
        checkpoint_hash: "checkpoint-a".to_owned(),
        next_cursor: 257,
        entries_processed: 1,
        names: BTreeSet::from(["api.example.com".to_owned()]),
        tiles: vec![crate::ct_static::StaticTile {
            path: "tile/data/001".to_owned(),
            checkpoint_size: 512,
            checkpoint_hash: "checkpoint-a".to_owned(),
            content_hash: format!("{:x}", Sha256::digest(&first_payload)),
            payload: first_payload,
        }],
        ..crate::ct_static::StaticCtBatch::default()
    };
    db.store_ct_static_batch(log_url, &first).unwrap();

    let conflicting_payload = b"rewritten payload".to_vec();
    let conflicting = crate::ct_static::StaticCtBatch {
        checkpoint_origin: "ct.example/2026h2".to_owned(),
        checkpoint_size: 768,
        checkpoint_hash: "checkpoint-b".to_owned(),
        next_cursor: 513,
        entries_processed: 256,
        names: BTreeSet::from(["must-not-commit.example.com".to_owned()]),
        tiles: vec![crate::ct_static::StaticTile {
            path: "tile/data/001".to_owned(),
            checkpoint_size: 768,
            checkpoint_hash: "checkpoint-b".to_owned(),
            content_hash: format!("{:x}", Sha256::digest(&conflicting_payload)),
            payload: conflicting_payload,
        }],
        ..crate::ct_static::StaticCtBatch::default()
    };

    assert!(db.store_ct_static_batch(log_url, &conflicting).is_err());
    assert_eq!(db.ct_global_cursor(log_url).unwrap(), Some(257));
    assert_eq!(
        db.ct_names_for_domain("example.com", 10).unwrap(),
        vec!["api.example.com"]
    );
}

#[test]
fn expired_static_ct_commit_keeps_tiles_names_and_cursor_atomic() {
    let db = Database::in_memory().unwrap();
    let log_url = "https://ct.example/2026h2/";
    db.store_ct_global_batch(log_url, 100, &BTreeSet::new())
        .unwrap();
    let payload = b"must-not-be-visible".to_vec();
    let batch = crate::ct_static::StaticCtBatch {
        checkpoint_origin: "ct.example/2026h2".to_owned(),
        checkpoint_size: 512,
        checkpoint_hash: "checkpoint-deadline".to_owned(),
        next_cursor: 101,
        entries_processed: 1,
        names: BTreeSet::from(["deadline.example.com".to_owned()]),
        tiles: vec![crate::ct_static::StaticTile {
            path: "tile/data/deadline".to_owned(),
            checkpoint_size: 512,
            checkpoint_hash: "checkpoint-deadline".to_owned(),
            content_hash: format!("{:x}", Sha256::digest(&payload)),
            payload,
        }],
        ..crate::ct_static::StaticCtBatch::default()
    };
    let cancellation = AtomicBool::new(false);

    assert!(
        db.store_ct_static_batch_until_cancelled(
            log_url,
            &batch,
            Some(Instant::now()),
            &cancellation,
        )
        .is_err()
    );
    assert_eq!(db.ct_global_cursor(log_url).unwrap(), Some(100));
    assert!(
        db.ct_names_for_domain("example.com", 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        db.ct_static_tile(log_url, "tile/data/deadline", 512, "checkpoint-deadline",)
            .unwrap()
            .is_none()
    );
}

#[test]
fn cancelled_global_ct_commit_stops_waiting_for_the_shared_mutex() {
    let db = Database::in_memory().unwrap();
    let log_url = "https://ct.example/log/";
    db.store_ct_global_batch(log_url, 100, &BTreeSet::new())
        .unwrap();
    let shared_lock = db.lock().unwrap();
    let cancellation = Arc::new(AtomicBool::new(false));
    let worker_cancellation = Arc::clone(&cancellation);
    let worker_db = db.clone();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = worker_db.store_ct_global_batch_until_cancelled(
            log_url,
            101,
            &BTreeSet::from(["cancelled.example.com".to_owned()]),
            None,
            worker_cancellation.as_ref(),
        );
        result_tx.send(result).unwrap();
    });

    started_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    cancellation.store(true, Ordering::Release);
    let result = result_rx
        .recv_timeout(Duration::from_millis(500))
        .expect("le commit CT est reste bloque sur le mutex partage");
    assert!(result.unwrap_err().to_string().contains("annulée"));
    drop(shared_lock);
    worker.join().unwrap();
    assert_eq!(db.ct_global_cursor(log_url).unwrap(), Some(100));
    assert!(
        db.ct_names_for_domain("example.com", 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn wildcard_and_normalized_observations_are_persistent() {
    let db = Database::in_memory().unwrap();
    db.store_wildcard_cache(
        "example.com",
        &BTreeSet::from(["A:192.0.2.10".to_owned()]),
        Some(42),
        std::time::Duration::from_secs(600),
        true,
    )
    .unwrap();
    let wildcard = db.wildcard_cache("example.com").unwrap().unwrap();
    assert_eq!(wildcard.soa_serial, Some(42));
    assert!(wildcard.signature.contains("A:192.0.2.10"));
    assert_eq!(wildcard.algorithm_version, 4);

    db.lock()
            .unwrap()
            .execute(
                "UPDATE wildcard_cache SET signature_json='[\"A:*\"]', algorithm_version=1 WHERE zone='example.com'",
                [],
            )
            .unwrap();
    let legacy = db.wildcard_cache("example.com").unwrap().unwrap();
    assert!(legacy.signature.is_empty());
    assert_eq!(legacy.algorithm_version, 1);

    db.store_wildcard_cache_with_algorithm(
        "example.com",
        &BTreeSet::from(["A:192.0.2.20".to_owned()]),
        Some(43),
        std::time::Duration::from_secs(600),
        true,
        5,
    )
    .unwrap();
    let consensus = db.wildcard_cache("example.com").unwrap().unwrap();
    assert_eq!(consensus.algorithm_version, 5);
    assert!(consensus.signature.contains("A:192.0.2.20"));
    assert!(
        db.store_wildcard_cache_with_algorithm(
            "example.com",
            &BTreeSet::new(),
            None,
            std::time::Duration::from_secs(60),
            false,
            6,
        )
        .is_err()
    );

    db.store_observations(
        "example.com",
        vec![ObservationInput {
            fqdn: "api.example.com".to_owned(),
            kind: "web".to_owned(),
            source: "web:https://www.example.com/".to_owned(),
            value: "hash".to_owned(),
        }],
    )
    .unwrap();
    assert_eq!(
        db.observation_names("example.com", "web:https://www.example.com/")
            .unwrap(),
        vec!["api.example.com"]
    );

    db.store_resolver_metrics(&[ResolverMetric {
        resolver: "1.1.1.1".to_owned(),
        requests: 10,
        successes: 9,
        failures: 1,
        average_ms: 12,
        consecutive_failures: 0,
    }])
    .unwrap();
    let resolver = db.resolver_history().unwrap().remove("1.1.1.1").unwrap();
    assert_eq!(resolver.requests, 10);
    assert_eq!(resolver.average_ms, 12);
}

#[test]
fn failing_automatic_sources_enter_cooldown_and_recover() {
    let db = Database::in_memory().unwrap();
    for _ in 0..3 {
        db.record_source_result("slow", 0, 20_000, Some("timeout"))
            .unwrap();
    }
    assert!(
        db.source_cooldowns(std::time::Duration::from_secs(86_400))
            .unwrap()
            .contains("slow")
    );
    let diagnostic = db
        .source_diagnostics(std::time::Duration::from_secs(86_400))
        .unwrap()
        .remove("slow")
        .unwrap();
    assert_eq!(diagnostic.consecutive_failures, 3);
    assert!(diagnostic.next_retry.is_some());
    assert_eq!(diagnostic.last_error.as_deref(), Some("timeout"));

    db.store_source_metadata(
        "commoncrawl.latest_endpoint",
        "https://index.commoncrawl.org/x",
    )
    .unwrap();
    assert_eq!(
        db.source_metadata(
            "commoncrawl.latest_endpoint",
            std::time::Duration::from_secs(3_600)
        )
        .unwrap()
        .as_deref(),
        Some("https://index.commoncrawl.org/x")
    );
    db.store_source_metadata(
        "source.retry_until.slow",
        &now_epoch().saturating_add(7_200).to_string(),
    )
    .unwrap();
    assert!(
        db.source_diagnostics(std::time::Duration::from_secs(60))
            .unwrap()["slow"]
            .retry_in_seconds
            .is_some_and(|seconds| seconds > 7_000)
    );
    db.record_source_result("slow", 4, 100, None).unwrap();
    assert!(
        !db.source_cooldowns(std::time::Duration::from_secs(86_400))
            .unwrap()
            .contains("slow")
    );
    assert!(
        db.source_diagnostics(std::time::Duration::from_secs(86_400))
            .unwrap()["slow"]
            .next_retry
            .is_none()
    );
}

#[test]
fn degraded_and_deferred_sources_never_enter_failure_cooldown() {
    let db = Database::in_memory().unwrap();
    for _ in 0..3 {
        db.record_source_degraded_with_counts("partial", 10, 4, 100, "page suivante limitée")
            .unwrap();
        db.record_source_deferred("quota", 5, "Retry-After=60s")
            .unwrap();
    }

    let cooldowns = db
        .source_cooldowns(std::time::Duration::from_secs(86_400))
        .unwrap();
    assert!(!cooldowns.contains("partial"));
    assert!(!cooldowns.contains("quota"));

    let diagnostics = db
        .source_diagnostics(std::time::Duration::from_secs(86_400))
        .unwrap();
    let partial = &diagnostics["partial"];
    assert_eq!(partial.requests, 3);
    assert_eq!(partial.successes, 0);
    assert_eq!(partial.failures, 0);
    assert_eq!(partial.degraded, 3);
    assert_eq!(partial.deferred, 0);
    assert_eq!(partial.consecutive_failures, 0);
    assert_eq!(partial.names, 30);
    assert_eq!(partial.novel_names, 12);
    assert_eq!(partial.novel_requests, 3);
    assert_eq!(partial.last_status, "degraded");
    assert_eq!(partial.last_error.as_deref(), Some("page suivante limitée"));
    assert!(partial.next_retry.is_none());

    let quota = &diagnostics["quota"];
    assert_eq!(quota.requests, 3);
    assert_eq!(quota.successes, 0);
    assert_eq!(quota.failures, 0);
    assert_eq!(quota.degraded, 0);
    assert_eq!(quota.deferred, 3);
    assert_eq!(quota.consecutive_failures, 0);
    assert_eq!(quota.novel_requests, 0);
    assert_eq!(quota.last_status, "deferred");
    assert_eq!(quota.last_error.as_deref(), Some("Retry-After=60s"));
    assert!(quota.next_retry.is_none());
}

#[test]
fn existing_source_stats_keep_raw_names_and_start_fresh_yield_metrics() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let connection = Connection::open(temporary.path()).unwrap();
    connection
        .execute_batch(
            r#"
                CREATE TABLE source_stats (
                    source TEXT PRIMARY KEY,
                    requests INTEGER NOT NULL DEFAULT 0,
                    successes INTEGER NOT NULL DEFAULT 0,
                    failures INTEGER NOT NULL DEFAULT 0,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    names INTEGER NOT NULL DEFAULT 0,
                    total_ms INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    last_used INTEGER NOT NULL
                );
                INSERT INTO source_stats(
                    source, requests, successes, failures, consecutive_failures,
                    names, total_ms, last_error, last_used
                ) VALUES ('legacy', 4, 4, 0, 0, 250, 400, NULL, 1);
                PRAGMA user_version=8;
                "#,
        )
        .unwrap();
    drop(connection);

    let db = Database::open(temporary.path()).unwrap();
    let columns: i64 = db
        .lock()
        .unwrap()
        .query_row(
            r#"SELECT COUNT(*) FROM pragma_table_info('source_stats')
                   WHERE name IN (
                       'novel_names', 'novel_requests', 'novel_total_ms',
                       'degraded', 'deferred', 'last_status'
                   )"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(columns, 6);
    let score_before = db.source_scores().unwrap()["legacy"];

    db.record_source_result("legacy", 3, 100, None).unwrap();
    let diagnostic = db
        .source_diagnostics(std::time::Duration::ZERO)
        .unwrap()
        .remove("legacy")
        .unwrap();
    assert_eq!(diagnostic.names, 250);
    assert_eq!(diagnostic.novel_names, 3);
    assert_eq!(diagnostic.novel_requests, 1);
    assert_eq!(diagnostic.degraded, 0);
    assert_eq!(diagnostic.deferred, 0);
    assert_eq!(diagnostic.last_status, "success");
    assert!(db.source_scores().unwrap()["legacy"] > score_before);
    drop(db);

    let reopened = Database::open(temporary.path()).unwrap();
    reopened
        .record_source_result_with_counts("legacy", 11, 4, 200, None)
        .unwrap();
    let diagnostic = reopened
        .source_diagnostics(std::time::Duration::ZERO)
        .unwrap()
        .remove("legacy")
        .unwrap();
    assert_eq!(diagnostic.names, 261);
    assert_eq!(diagnostic.novel_names, 7);
    assert_eq!(diagnostic.novel_requests, 2);
    let yield_totals: (i64, i64, i64) = reopened
        .lock()
        .unwrap()
        .query_row(
            r#"SELECT novel_names, novel_requests, novel_total_ms
                   FROM source_stats WHERE source='legacy'"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(yield_totals, (7, 2, 300));
}

#[test]
fn source_scores_reward_marginal_yield_and_penalize_zero_yield() {
    let db = Database::in_memory().unwrap();
    db.record_source_result("useful", 10, 1_000, None).unwrap();
    db.record_source_result("empty", 0, 100, None).unwrap();
    db.record_source_result_with_counts("clean-page", 10, 5, 100, None)
        .unwrap();
    db.record_source_degraded_with_counts(
        "partial-page",
        10,
        5,
        100,
        "page 2 returned invalid JSON",
    )
    .unwrap();
    for _ in 0..3 {
        db.record_source_result("failing", 0, 20_000, Some("timeout"))
            .unwrap();
    }

    let scores = db.source_scores().unwrap();
    assert!(scores["useful"] > scores["empty"]);
    assert!(scores["empty"] > scores["failing"]);
    assert!(scores["useful"] > 1_000);
    assert!(scores["failing"] < 0);
    assert!(scores["clean-page"] > scores["partial-page"]);
    let diagnostics = db.source_diagnostics(std::time::Duration::ZERO).unwrap();
    let partial = &diagnostics["partial-page"];
    assert_eq!(partial.names, 10);
    assert_eq!(partial.novel_names, 5);
    assert_eq!(partial.failures, 0);
    assert_eq!(partial.degraded, 1);
    assert_eq!(partial.deferred, 0);
    assert_eq!(partial.consecutive_failures, 0);
    assert_eq!(partial.last_status, "degraded");
    assert_eq!(
        partial.last_error.as_deref(),
        Some("page 2 returned invalid JSON")
    );
}

#[test]
fn ct_materialization_is_bounded_permanent_and_idempotent() {
    let db = Database::in_memory().unwrap();
    let names = (0..500)
        .map(|index| format!("ct-{index:04}.example.com"))
        .collect::<BTreeSet<_>>();
    db.store_ct_global_batch("https://ct.example/log/", 500, &names)
        .unwrap();

    let first = db
        .materialize_ct_passive_cache_bounded("example.com", 17, true)
        .unwrap();
    assert_eq!(first.len(), 17);
    assert_eq!(
        db.ct_names_for_domain("example.com", 1_000).unwrap().len(),
        500
    );
    assert_eq!(
        db.observation_names("example.com", "passive:ct-direct")
            .unwrap()
            .len(),
        17
    );

    let tracked = first[0].clone();
    db.lock()
        .unwrap()
        .execute(
            r#"UPDATE observation_evidence
                      SET first_seen=11, last_seen=22, times_seen=9
                    WHERE root_domain='example.com'
                      AND source='passive:ct-direct'
                      AND name_id=(SELECT id FROM observed_names WHERE fqdn=?1)"#,
            [&tracked],
        )
        .unwrap();

    let second = db
        .materialize_ct_passive_cache_bounded("example.com", 17, true)
        .unwrap();
    assert_eq!(second, first);
    let evidence: (i64, i64, i64) = db
        .lock()
        .unwrap()
        .query_row(
            r#"SELECT first_seen, last_seen, times_seen
                     FROM observation_evidence
                    WHERE root_domain='example.com'
                      AND source='passive:ct-direct'
                      AND name_id=(SELECT id FROM observed_names WHERE fqdn=?1)"#,
            [&tracked],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(evidence, (11, 22, 9));
}

#[test]
fn expired_ct_materialization_never_writes_or_refreshes_cache() {
    let db = Database::in_memory().unwrap();
    db.store_ct_global_batch(
        "https://ct.example/log/",
        1,
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();

    assert!(
        db.materialize_ct_passive_cache_bounded_until(
            "example.com",
            10,
            true,
            Some(Instant::now()),
        )
        .is_err()
    );
    assert!(
        db.observation_names("example.com", "passive:ct-direct")
            .unwrap()
            .is_empty()
    );
    assert!(
        db.passive_cache_bounded("example.com", "ct-direct", 10)
            .unwrap()
            .is_none()
    );
}

#[test]
fn ct_materialization_does_not_wait_past_its_deadline_for_a_locked_database() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let db = Database::open(temporary.path()).unwrap();
    db.store_ct_global_batch(
        "https://ct.example/log/",
        1,
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();
    let locker = Connection::open(temporary.path()).unwrap();
    locker.execute_batch("BEGIN IMMEDIATE").unwrap();

    let started = Instant::now();
    let result = db.materialize_ct_passive_cache_bounded_until(
        "example.com",
        10,
        true,
        Some(Instant::now() + Duration::from_millis(150)),
    );

    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    locker.execute_batch("ROLLBACK").unwrap();
    assert!(
        db.observation_names("example.com", "passive:ct-direct")
            .unwrap()
            .is_empty()
    );
    assert!(
        db.passive_cache_bounded("example.com", "ct-direct", 10)
            .unwrap()
            .is_none()
    );
}

#[test]
fn cancelled_ct_materialization_exits_while_the_shared_mutex_remains_locked() {
    let db = Database::in_memory().unwrap();
    db.store_ct_global_batch(
        "https://ct.example/log/",
        1,
        &BTreeSet::from(["api.example.com".to_owned()]),
    )
    .unwrap();
    let worker_db = db.clone();
    let cancellation = Arc::new(AtomicBool::new(false));
    let worker_cancellation = Arc::clone(&cancellation);
    let shared_lock = db.lock().unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = worker_db.materialize_ct_passive_cache_bounded_until_cancelled(
            "example.com",
            10,
            true,
            None,
            worker_cancellation,
        );
        result_tx.send(result).unwrap();
    });

    started_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    cancellation.store(true, Ordering::Release);
    let result = result_rx
        .recv_timeout(Duration::from_millis(500))
        .expect("le worker CT est resté bloqué sur le mutex partagé");
    assert!(result.unwrap_err().to_string().contains("annulée"));
    drop(shared_lock);
    worker.join().unwrap();
    assert!(
        db.observation_names("example.com", "passive:ct-direct")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unversioned_legacy_database_is_backed_up_before_migration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fellaga.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("CREATE TABLE legacy_rows(value TEXT NOT NULL)", [])
        .unwrap();
    connection
        .execute("INSERT INTO legacy_rows(value) VALUES ('preserved')", [])
        .unwrap();
    drop(connection);

    let database = Database::open(&path).unwrap();
    drop(database);

    let backup = std::fs::read_dir(directory.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .find(|candidate| {
            candidate
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains(".pre-v8-") && name.ends_with(".bak"))
        })
        .expect("unversioned legacy database had no safety backup");
    let backup = Connection::open(backup).unwrap();
    assert_eq!(
        backup
            .query_row("SELECT value FROM legacy_rows", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "preserved"
    );
    assert_eq!(
        backup
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn checkpoint_domain_is_immutable_and_resume_requeues_discovery_actions() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    assert!(
        db.upsert_checkpoint(scan_id, "other.example", "running", "bad")
            .is_err()
    );
    assert!(
        db.resumable_checkpoint("other.example", "latest")
            .unwrap()
            .is_none()
    );
    db.upsert_checkpoint(scan_id, "example.com", "running", "good")
        .unwrap();
    db.persist_scan_seed_candidates(
        scan_id,
        &[(
            "seed.example.com".to_owned(),
            BTreeSet::from(["passive:test".to_owned()]),
            1,
        )],
        1,
    )
    .unwrap();
    let seed = "seed.example.com".to_owned();
    assert_eq!(
        db.pending_scan_seed_candidates(scan_id, 1).unwrap().len(),
        1
    );
    db.requeue_unstarted_scan_seed_candidates(scan_id, std::slice::from_ref(&seed))
        .unwrap();
    assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 1);
    assert_eq!(
        db.pending_scan_seed_candidates(scan_id, 1).unwrap().len(),
        1
    );
    db.enqueue_discovery_actions(
        scan_id,
        &[DiscoveryActionInput {
            fqdn: Some("api.example.com".to_owned()),
            zone: "example.com".to_owned(),
            kind: "dns".to_owned(),
            generator: "resume-regression".to_owned(),
            context_key: "global".to_owned(),
            priority_class: 0,
            predicted_unique_live: 1.0,
            predicted_cost: 1.0,
        }],
    )
    .unwrap();
    let first = db.claim_discovery_actions(scan_id, 1).unwrap();
    assert_eq!(first.len(), 1);

    db.pause_scan(scan_id, 0, 0, 0, 1, &[]).unwrap();
    db.reopen_scan(scan_id).unwrap();
    assert_eq!(
        db.pending_scan_seed_candidates(scan_id, 1).unwrap().len(),
        1
    );
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                "SELECT attempts FROM scan_seed_candidates WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "unstarted claims must survive deadline requeue and resume without consuming a retry"
    );
    db.mark_scan_seed_candidates_started(scan_id, std::slice::from_ref(&seed))
        .unwrap();
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                "SELECT attempts FROM scan_seed_candidates WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    db.update_cache_outcomes(Some(scan_id), &[], &[], std::slice::from_ref(&seed), 60)
        .unwrap();
    db.mark_scan_seed_candidates_done(scan_id, std::slice::from_ref(&seed))
        .unwrap();
    assert_eq!(
        db.pending_scan_seed_candidates(scan_id, 1).unwrap().len(),
        1
    );
    db.requeue_unstarted_scan_seed_candidates(scan_id, std::slice::from_ref(&seed))
        .unwrap();
    assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 1);
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                "SELECT attempts FROM scan_seed_candidates WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
        "an unstarted retry must preserve attempts from earlier real DNS work"
    );
    let resumed = db.claim_discovery_actions(scan_id, 1).unwrap();
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].id, first[0].id);
}

#[test]
fn exhausted_rows_are_excluded_from_every_candidate_claim_and_loop_count() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let seed = "seed-exhausted.example.com".to_owned();
    db.persist_scan_seed_candidates(
        scan_id,
        &[(
            seed.clone(),
            BTreeSet::from(["passive:test".to_owned()]),
            10,
        )],
        10,
    )
    .unwrap();
    db.persist_scan_candidates(
        scan_id,
        "example.com",
        &[("active-exhausted".to_owned(), "builtin".to_owned(), 10)],
    )
    .unwrap();
    db.ensure_scan_recursive_words(scan_id, &["recursive-exhausted".to_owned()])
        .unwrap();
    db.persist_scan_recursive_parents(scan_id, 1, &["example.com".to_owned()])
        .unwrap();
    assert_eq!(
        db.refill_scan_recursive_candidates(scan_id, 1, 1).unwrap(),
        1
    );
    {
        let connection = db.lock().unwrap();
        for table in [
            "scan_seed_candidates",
            "scan_candidates",
            "scan_recursive_candidates",
        ] {
            connection
                .execute(
                    &format!("UPDATE {table} SET attempts=3, status='queued' WHERE scan_id=?1"),
                    [scan_id],
                )
                .unwrap();
        }
    }

    assert!(
        db.pending_scan_seed_candidates(scan_id, 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        db.claim_scan_seed_candidates_by_name(scan_id, std::slice::from_ref(&seed))
            .unwrap()
            .is_empty()
    );
    assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 0);
    assert!(db.pending_scan_candidates(scan_id, 10).unwrap().is_empty());
    assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 0);
    assert_eq!(
        db.pending_scan_candidate_count_eligible(scan_id, true)
            .unwrap(),
        0
    );
    assert!(
        db.pending_scan_recursive_candidates(scan_id, 1, 10)
            .unwrap()
            .is_empty()
    );
    assert!(!db.scan_recursive_depth_has_more(scan_id, 1).unwrap());
    assert!(!db.scan_recursive_has_more(scan_id).unwrap());
}

#[test]
fn reopen_scan_requeues_only_rows_with_retry_budget_in_all_three_queues() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.upsert_checkpoint(scan_id, "example.com", "running", "options")
        .unwrap();
    {
        let connection = db.lock().unwrap();
        connection
            .execute(
                r#"INSERT INTO scan_seed_candidates(
                           scan_id, fqdn, priority, sources_json, attempts, status
                       ) VALUES
                           (?1, 'exhausted.example.com', 2, '[]', 3, 'queued'),
                           (?1, 'retry.example.com', 1, '[]', 2, 'processing')"#,
                [scan_id],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO scan_candidates(
                           scan_id, fqdn, relative_name, priority, generator, attempts, status
                       ) VALUES
                           (?1, 'exhausted.example.com', 'exhausted', 2, 'test', 3, 'processing'),
                           (?1, 'retry.example.com', 'retry', 1, 'test', 2, 'processing')"#,
                [scan_id],
            )
            .unwrap();
        connection
                .execute(
                    r#"INSERT INTO scan_recursive_candidates(
                           scan_id, fqdn, parent, depth, word, attempts, status
                       ) VALUES
                           (?1, 'exhausted.example.com', 'example.com', 1, 'exhausted', 3, 'queued'),
                           (?1, 'retry.example.com', 'example.com', 1, 'retry', 2, 'processing')"#,
                    [scan_id],
                )
                .unwrap();
    }
    db.pause_scan(scan_id, 0, 0, 0, 1, &[]).unwrap();
    db.reopen_scan(scan_id).unwrap();

    let connection = db.lock().unwrap();
    for table in [
        "scan_seed_candidates",
        "scan_candidates",
        "scan_recursive_candidates",
    ] {
        let rows = connection
            .prepare(&format!(
                "SELECT fqdn, status FROM {table} WHERE scan_id=?1 ORDER BY fqdn"
            ))
            .unwrap()
            .query_map([scan_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("exhausted.example.com".to_owned(), "done".to_owned()),
                ("retry.example.com".to_owned(), "queued".to_owned()),
            ],
            "resume state mismatch for {table}"
        );
    }
}

#[test]
fn live_outcome_wins_over_duplicate_negative_and_error_in_one_commit() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "api.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.10".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        resolver_count: 2,
        authoritative_validation: false,
    };
    let finding = Finding {
        fqdn: fqdn.clone(),
        records: answer.records.clone(),
        sources: BTreeSet::from(["dns:test".to_owned()]),
        wildcard: false,
        state: ObservationState::Live,
        last_verified_at: answer.last_verified_at,
        ..Finding::default()
    };
    db.persist_findings(scan_id, "example.com", &[finding], 60)
        .unwrap();
    db.update_cache_outcomes(
        Some(scan_id),
        &[answer],
        std::slice::from_ref(&fqdn),
        std::slice::from_ref(&fqdn),
        60,
    )
    .unwrap();

    assert!(matches!(
        db.fresh_cache(std::slice::from_ref(&fqdn))
            .unwrap()
            .get(&fqdn),
        Some(CachedAnswer::Positive(_))
    ));
    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT active, verification_state FROM subdomains WHERE fqdn=?1",
                [&fqdn],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap(),
        (1, "live".to_owned())
    );
    assert_eq!(
            connection
                .query_row(
                    "SELECT group_concat(outcome, ',') FROM dns_verifications WHERE scan_id=?1 AND fqdn=?2",
                    params![scan_id, fqdn],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "live"
        );
}

#[test]
fn off_zone_wildcard_ambiguity_cannot_delete_an_unrelated_cache_entry() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "api.other.example".to_owned();
    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.20".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        resolver_count: 2,
        authoritative_validation: false,
    };
    db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 60)
        .unwrap();
    assert!(
        db.record_current_wildcard_ambiguities(
            scan_id,
            "example.com",
            std::slice::from_ref(&answer),
        )
        .is_err()
    );
    assert!(matches!(
        db.fresh_cache(std::slice::from_ref(&fqdn))
            .unwrap()
            .get(&fqdn),
        Some(CachedAnswer::Positive(_))
    ));
}

#[test]
fn live_wildcard_finding_is_audited_but_never_materialized_as_live() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "random.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.30".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        resolver_count: 2,
        authoritative_validation: false,
    };
    db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 60)
        .unwrap();
    db.persist_findings(
        scan_id,
        "example.com",
        &[Finding {
            fqdn: fqdn.clone(),
            records: answer.records.clone(),
            sources: BTreeSet::from(["dns:initial-live".to_owned()]),
            wildcard: false,
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            ..Finding::default()
        }],
        60,
    )
    .unwrap();
    assert!(
        db.lock()
            .unwrap()
            .query_row(
                "SELECT last_verified_at FROM subdomains WHERE fqdn=?1",
                [&fqdn],
                |row| row.get::<_, Option<i64>>(0),
            )
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        db.fresh_cache(std::slice::from_ref(&fqdn))
            .unwrap()
            .get(&fqdn),
        Some(CachedAnswer::Positive(_))
    ));
    let finding = Finding {
        fqdn: fqdn.clone(),
        records: answer.records,
        sources: BTreeSet::from(["dns:wildcard".to_owned()]),
        wildcard: true,
        state: ObservationState::Live,
        last_verified_at: answer.last_verified_at,
        ..Finding::default()
    };
    db.persist_findings(scan_id, "example.com", &[finding], 60)
        .unwrap();

    assert!(
        !db.fresh_cache(std::slice::from_ref(&fqdn))
            .unwrap()
            .contains_key(&fqdn),
        "a wildcard finding must purge the provisional positive cache"
    );

    let connection = db.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT active, verification_state, last_verified_at FROM subdomains WHERE fqdn=?1",
                [&fqdn],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .unwrap(),
        (0, "unverified".to_owned(), None)
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT active FROM dns_records WHERE fqdn=?1",
                [&fqdn],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT state, wildcard FROM scan_findings WHERE scan_id=?1 AND fqdn=?2",
                params![scan_id, fqdn],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap(),
        ("live".to_owned(), 1)
    );
}

#[test]
fn ordinary_historical_finding_keeps_its_positive_cache_history() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "old.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.31".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(now_epoch()),
        resolver_count: 2,
        authoritative_validation: false,
    };
    db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 60)
        .unwrap();
    db.persist_findings(
        scan_id,
        "example.com",
        &[Finding {
            fqdn: fqdn.clone(),
            records: answer.records,
            sources: BTreeSet::from(["history:test".to_owned()]),
            wildcard: false,
            state: ObservationState::Historical,
            last_verified_at: answer.last_verified_at,
            ..Finding::default()
        }],
        60,
    )
    .unwrap();

    assert!(matches!(
        db.fresh_cache(std::slice::from_ref(&fqdn))
            .unwrap()
            .get(&fqdn),
        Some(CachedAnswer::Positive(_))
    ));
    assert_eq!(
        db.lock()
            .unwrap()
            .query_row(
                "SELECT active, verification_state FROM subdomains WHERE fqdn=?1",
                [&fqdn],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap(),
        (0, "historical".to_owned())
    );
}

#[test]
fn persistent_counters_and_legacy_bandits_tolerate_extreme_values() {
    let db = Database::in_memory().unwrap();
    let metric = ResolverMetric {
        resolver: "resolver.test:53".to_owned(),
        requests: u64::MAX,
        successes: u64::MAX,
        failures: u64::MAX,
        average_ms: u64::MAX,
        consecutive_failures: u64::MAX,
    };
    db.store_resolver_metrics(std::slice::from_ref(&metric))
        .unwrap();
    db.store_resolver_metrics(&[metric]).unwrap();
    let history = db.resolver_history().unwrap();
    let stored = &history["resolver.test:53"];
    assert_eq!(stored.requests, i64::MAX as u64);
    assert_eq!(stored.successes, i64::MAX as u64);
    assert_eq!(stored.failures, i64::MAX as u64);
    assert_eq!(stored.consecutive_failures, i64::MAX as u64);

    db.record_source_result_with_counts("overflow-source", usize::MAX, usize::MAX, u128::MAX, None)
        .unwrap();
    db.record_source_result_with_counts("overflow-source", usize::MAX, usize::MAX, u128::MAX, None)
        .unwrap();
    let source_counters = db
        .lock()
        .unwrap()
        .query_row(
            r#"SELECT requests, successes, names, novel_names,
                          novel_requests, novel_total_ms, total_ms
                   FROM source_stats WHERE source='overflow-source'"#,
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        source_counters,
        (2, 2, i64::MAX, i64::MAX, 2, i64::MAX, i64::MAX)
    );

    db.lock()
        .unwrap()
        .execute(
            r#"INSERT INTO generator_bandits(
                       context, generator, alpha, beta, pulls, rewards, last_seen
                   ) VALUES ('suffix:com', 'number-neighbor', -1.0e308, -1.0e308,
                             -9223372036854775808, -1, 1)"#,
            [],
        )
        .unwrap();
    let scores = db.generator_scores("example.com").unwrap();
    assert!((650..=2_650).contains(&scores["number-neighbor"]));
}

#[test]
fn scan_summary_counts_saturate_instead_of_wrapping_negative() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    db.finish_scan(
        scan_id,
        "interrupted",
        usize::MAX,
        usize::MAX,
        usize::MAX,
        u128::MAX,
        &[],
    )
    .unwrap();
    let stored = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT candidates, found, cache_hits, duration_ms FROM scans WHERE id=?1",
            [scan_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap();
    let expected = usize_to_i64_saturating(usize::MAX);
    assert_eq!(stored, (expected, expected, expected, i64::MAX));
}

#[test]
fn resumed_axfr_snapshot_replaces_attempts_without_duplicate_metrics() {
    let db = Database::in_memory().unwrap();
    let scan_id = db.create_scan("example.com", &json!({})).unwrap();
    let attempt = |nameserver: &str, status| AxfrAttempt {
        nameserver: nameserver.to_owned(),
        address: "192.0.2.53:53".to_owned(),
        status,
        error: None,
        records: Vec::new(),
        names: BTreeSet::new(),
    };
    db.save_axfr_attempts(
        scan_id,
        &[
            attempt("ns1.example.com", crate::model::AxfrStatus::Refused),
            attempt("ns2.example.com", crate::model::AxfrStatus::Timeout),
        ],
    )
    .unwrap();
    db.save_axfr_attempts(
        scan_id,
        &[attempt(
            "ns1.example.com",
            crate::model::AxfrStatus::Success,
        )],
    )
    .unwrap();

    let rows = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*), SUM(status='success') FROM axfr_attempts WHERE scan_id=?1",
            [scan_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap();
    assert_eq!(rows, (1, 1));
}

#[test]
fn ip_hostname_cache_is_permanent_and_failures_never_delete_names() {
    let db = Database::in_memory().unwrap();
    let address: IpAddr = "1.1.1.1".parse().unwrap();
    assert!(
        db.ip_hostname_cache("shodan-internetdb", address, 256)
            .unwrap()
            .is_none()
    );

    db.store_ip_hostname_success(
        "shodan-internetdb",
        address,
        &BTreeSet::from([
            "a.example.com".to_owned(),
            "b.example.com".to_owned(),
            "invalid host".to_owned(),
        ]),
    )
    .unwrap();
    db.store_ip_hostname_success(
        "shodan-internetdb",
        address,
        &BTreeSet::from(["b.example.com".to_owned(), "c.example.com".to_owned()]),
    )
    .unwrap();
    let before_failure = db
        .ip_hostname_cache("shodan-internetdb", address, 256)
        .unwrap()
        .unwrap();
    assert_eq!(before_failure.status, "success");
    assert_eq!(
        before_failure.hostnames,
        BTreeSet::from([
            "a.example.com".to_owned(),
            "b.example.com".to_owned(),
            "c.example.com".to_owned(),
        ])
    );

    db.store_ip_hostname_failure("shodan-internetdb", address, "temporary failure")
        .unwrap();
    let after_failure = db
        .ip_hostname_cache("shodan-internetdb", address, 256)
        .unwrap()
        .unwrap();
    assert_eq!(after_failure.status, "error");
    assert_eq!(after_failure.hostnames, before_failure.hostnames);
    assert_eq!(
        after_failure.last_success_at,
        before_failure.last_success_at
    );
    assert!(db.ip_hostname_cache("INVALID", address, 1).is_err());
}
