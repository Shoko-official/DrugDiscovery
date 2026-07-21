use std::{collections::BTreeMap, fs, path::PathBuf};

use sqlparser::{
    ast::{
        Action, AlterColumnOperation, AlterTableOperation, CreatePolicyCommand, CreatePolicyType,
        DataType, ExactNumberInfo, FunctionReturnType, GrantObjects, GranteesType, Privileges,
        Set as SetStatement, Statement, TableConstraint, TriggerEvent, TriggerObject,
        TriggerObjectKind, TriggerPeriod,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};

fn migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations")
}

fn parse_migration(name: &str) -> Vec<Statement> {
    let path = migrations_dir().join(name);
    let sql = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    Parser::parse_sql(&PostgreSqlDialect {}, &sql)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn read_migration(name: &str) -> String {
    let path = migrations_dir().join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

#[test]
fn every_migration_parses_as_postgresql() {
    let mut migrations = fs::read_dir(migrations_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect::<Vec<_>>();
    migrations.sort();

    assert!(!migrations.is_empty());
    for path in migrations {
        let sql = fs::read_to_string(&path).unwrap();
        let statements = Parser::parse_sql(&PostgreSqlDialect {}, &sql)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        assert!(
            !statements.iter().any(|statement| matches!(
                statement,
                Statement::StartTransaction { .. }
                    | Statement::Commit { .. }
                    | Statement::Rollback { .. }
            )),
            "migration transaction ownership belongs to the runner: {}",
            path.display()
        );
    }
}

#[test]
fn decision_event_migration_enforces_the_storage_contract() {
    let statements = parse_migration("0002_decision_event_contract.sql");

    let alter_table = statements
        .iter()
        .find_map(|statement| match statement {
            Statement::AlterTable(value) if value.name.to_string() == "scientific_event" => {
                Some(value)
            }
            _ => None,
        })
        .expect("scientific_event must be altered");

    assert!(alter_table.operations.iter().any(|operation| matches!(
        operation,
        AlterTableOperation::DropConstraint { name, .. }
            if name.value == "scientific_event_aggregate_version_check"
    )));
    assert!(alter_table.operations.iter().any(|operation| matches!(
        operation,
        AlterTableOperation::AlterColumn {
            column_name,
            op: AlterColumnOperation::SetDataType {
                data_type: DataType::Numeric(ExactNumberInfo::None),
                using: Some(_),
                ..
            },
        } if column_name.value == "aggregate_version"
    )));
    assert!(alter_table.operations.iter().any(|operation| matches!(
        operation,
        AlterTableOperation::AlterColumn {
            column_name,
            op: AlterColumnOperation::SetDataType {
                data_type: DataType::Text,
                using: Some(_),
                ..
            },
        } if column_name.value == "payload_sha256"
    )));

    let checks = alter_table
        .operations
        .iter()
        .filter_map(|operation| match operation {
            AlterTableOperation::AddConstraint {
                constraint: TableConstraint::Check(check),
                ..
            } => check
                .name
                .as_ref()
                .map(|name| (name.value.as_str(), check.expr.to_string())),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();

    let version_check = checks
        .get("scientific_event_aggregate_version_u64_check")
        .expect("positive u64 constraint is required");
    assert!(version_check.contains("aggregate_version >= 1"));
    assert!(version_check.contains("aggregate_version <= 18446744073709551615"));
    assert!(version_check.contains("aggregate_version = trunc(aggregate_version)"));

    let tenant_check = checks
        .get("scientific_event_tenant_id_check")
        .expect("tenant constraint is required");
    assert!(tenant_check.contains("tenant_id <> ''"));
    assert!(tenant_check.contains("btrim"));

    let digest_check = checks
        .get("scientific_event_payload_sha256_check")
        .expect("digest constraint is required");
    assert!(digest_check.contains("COLLATE \"C\""));
    assert!(digest_check.contains("^[0-9a-f]{64}$"));

    let signature_check = checks
        .get("scientific_event_signature_check")
        .expect("signature constraint is required");
    assert!(signature_check.contains("jsonb_typeof(signature) = 'object'"));
    assert!(signature_check.contains("signature <> '{}'::JSONB"));

    let function = statements
        .iter()
        .find_map(|statement| match statement {
            Statement::CreateFunction(value)
                if value.name.to_string() == "reject_scientific_event_mutation" =>
            {
                Some(value)
            }
            _ => None,
        })
        .expect("append-only trigger function is required");
    assert_eq!(
        function.language.as_ref().map(|value| value.value.as_str()),
        Some("plpgsql")
    );
    assert!(matches!(
        function.return_type,
        Some(FunctionReturnType::DataType(DataType::Trigger))
    ));
    let function_sql = function.to_string();
    assert!(function_sql.contains("RAISE EXCEPTION"));
    assert!(function_sql.contains("ERRCODE = '55000'"));

    let trigger = statements
        .iter()
        .find_map(|statement| match statement {
            Statement::CreateTrigger(value)
                if value.name.to_string() == "scientific_event_append_only" =>
            {
                Some(value)
            }
            _ => None,
        })
        .expect("append-only trigger is required");
    assert_eq!(trigger.table_name.to_string(), "scientific_event");
    assert_eq!(trigger.period, Some(TriggerPeriod::Before));
    assert_eq!(
        trigger.trigger_object,
        Some(TriggerObjectKind::ForEach(TriggerObject::Statement))
    );
    assert!(
        trigger
            .events
            .iter()
            .any(|event| matches!(event, TriggerEvent::Update(columns) if columns.is_empty()))
    );
    assert!(trigger.events.contains(&TriggerEvent::Delete));
    assert!(trigger.events.contains(&TriggerEvent::Truncate));
    assert_eq!(
        trigger
            .exec_body
            .as_ref()
            .map(|body| body.func_desc.name.to_string()),
        Some("reject_scientific_event_mutation".to_owned())
    );

    let revoke = statements
        .iter()
        .find_map(|statement| match statement {
            Statement::Revoke(value) => Some(value),
            _ => None,
        })
        .expect("runtime mutation privileges must be revoked");
    let Privileges::Actions(actions) = &revoke.privileges else {
        panic!("specific mutation privileges are required");
    };
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Update { columns: None }))
    );
    assert!(actions.contains(&Action::Delete));
    assert!(actions.contains(&Action::Truncate));
    assert!(matches!(
        &revoke.objects,
        Some(GrantObjects::Tables(tables))
            if tables.len() == 1 && tables[0].to_string() == "scientific_event"
    ));
    assert!(
        revoke.grantees.iter().any(|grantee| {
            grantee.grantee_type == GranteesType::Public && grantee.name.is_none()
        })
    );
}

#[test]
fn bounded_decision_envelope_migration_is_additive_and_validated() {
    let statements = parse_migration("0004_bounded_decision_envelope.sql");
    let operations = statements
        .iter()
        .filter_map(|statement| match statement {
            Statement::AlterTable(value) if value.name.to_string() == "public.scientific_event" => {
                Some(value.operations.iter())
            }
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>();

    let checks = operations
        .iter()
        .filter_map(|operation| match operation {
            AlterTableOperation::AddConstraint {
                constraint: TableConstraint::Check(check),
                not_valid: true,
            } => check
                .name
                .as_ref()
                .map(|name| (name.value.as_str(), check.expr.to_string())),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(checks.len(), 7);

    let tenant_check = checks
        .get("scientific_event_tenant_id_bytes_check")
        .expect("bounded tenant constraint is required");
    assert!(tenant_check.contains("octet_length"));
    assert!(tenant_check.contains("tenant_id"));
    assert!(tenant_check.contains("128"));

    for (constraint_name, column_name) in [
        ("scientific_event_event_type_envelope_check", "event_type"),
        (
            "scientific_event_schema_version_envelope_check",
            "schema_version",
        ),
        (
            "scientific_event_aggregate_type_envelope_check",
            "aggregate_type",
        ),
        (
            "scientific_event_aggregate_id_envelope_check",
            "aggregate_id",
        ),
    ] {
        let identifier_check = checks
            .get(constraint_name)
            .expect("bounded event identifier constraint is required");
        assert!(identifier_check.contains("char_length"));
        assert!(identifier_check.contains("octet_length"));
        assert!(identifier_check.contains(column_name));
        assert!(identifier_check.contains("200"));
        assert!(identifier_check.contains("800"));
    }

    let payload_check = checks
        .get("scientific_event_payload_bytes_check")
        .expect("bounded payload constraint is required");
    assert!(payload_check.contains("octet_length"));
    assert!(payload_check.contains("payload"));
    assert!(payload_check.contains("524288"));

    let signature_check = checks
        .get("scientific_event_signature_bytes_check")
        .expect("bounded signature constraint is required");
    assert!(signature_check.contains("octet_length"));
    assert!(signature_check.contains("signature"));
    assert!(signature_check.contains("20480"));

    let validated = operations
        .iter()
        .filter_map(|operation| match operation {
            AlterTableOperation::ValidateConstraint { name } => Some(name.value.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        validated,
        [
            "scientific_event_tenant_id_bytes_check",
            "scientific_event_event_type_envelope_check",
            "scientific_event_schema_version_envelope_check",
            "scientific_event_aggregate_type_envelope_check",
            "scientific_event_aggregate_id_envelope_check",
            "scientific_event_payload_bytes_check",
            "scientific_event_signature_bytes_check",
        ]
    );
    assert!(
        statements
            .iter()
            .all(|statement| matches!(statement, Statement::Set(_) | Statement::AlterTable(_)))
    );
}

#[test]
fn tenant_boundary_migration_is_role_agnostic_and_fail_closed() {
    let sql = read_migration("0003_postgres_tenant_boundary.sql");
    let normalized = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let statements = parse_migration("0003_postgres_tenant_boundary.sql");
    let table_operations = statements
        .iter()
        .filter_map(|statement| match statement {
            Statement::AlterTable(value) if value.name.to_string() == "public.scientific_event" => {
                Some(value.operations.iter())
            }
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>();

    assert!(normalized.contains("REVOKE CREATE ON SCHEMA public FROM PUBLIC"));
    assert!(normalized.contains("REVOKE ALL ON TABLE public.scientific_event FROM PUBLIC"));
    assert!(normalized.contains(
        "ALTER FUNCTION public.reject_scientific_event_mutation() SET search_path = pg_catalog"
    ));

    assert!(
        table_operations
            .iter()
            .any(|operation| matches!(operation, AlterTableOperation::EnableRowLevelSecurity))
    );
    assert!(
        table_operations
            .iter()
            .any(|operation| matches!(operation, AlterTableOperation::ForceRowLevelSecurity))
    );
    assert!(table_operations.iter().any(|operation| matches!(
        operation,
        AlterTableOperation::DropConstraint { name, .. }
            if name.value == "scientific_event_pkey"
    )));
    assert!(table_operations.iter().any(|operation| matches!(
        operation,
        AlterTableOperation::RenameConstraint { old_name, new_name }
            if old_name.value
                == "scientific_event_tenant_id_aggregate_type_aggregate_id_aggr_key"
                && new_name.value == "scientific_event_stream_version_key"
    )));

    let primary_key = table_operations
        .iter()
        .find_map(|operation| match operation {
            AlterTableOperation::AddConstraint {
                constraint: TableConstraint::PrimaryKey(primary_key),
                ..
            } => Some(primary_key),
            _ => None,
        })
        .expect("tenant-scoped primary key is required");
    assert_eq!(
        primary_key.name.as_ref().map(|name| name.value.as_str()),
        Some("scientific_event_pkey")
    );
    assert_eq!(
        primary_key
            .columns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["tenant_id", "event_id"]
    );

    let policies = statements
        .iter()
        .filter_map(|statement| match statement {
            Statement::CreatePolicy(policy) => Some((policy.name.value.as_str(), policy)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(policies.len(), 3);

    let expected_policies = [
        (
            "scientific_event_tenant_fence",
            CreatePolicyType::Restrictive,
            CreatePolicyCommand::All,
            true,
            true,
        ),
        (
            "scientific_event_tenant_select",
            CreatePolicyType::Permissive,
            CreatePolicyCommand::Select,
            true,
            false,
        ),
        (
            "scientific_event_tenant_insert",
            CreatePolicyType::Permissive,
            CreatePolicyCommand::Insert,
            false,
            true,
        ),
    ];

    for (name, policy_type, command, has_using, has_with_check) in expected_policies {
        let policy = policies.get(name).expect("tenant policy is required");
        assert_eq!(policy.table_name.to_string(), "public.scientific_event");
        assert_eq!(policy.policy_type, Some(policy_type));
        assert_eq!(policy.command, Some(command));
        assert_eq!(
            policy
                .to
                .as_ref()
                .map(|owners| owners.iter().map(ToString::to_string).collect::<Vec<_>>()),
            Some(vec!["PUBLIC".to_owned()])
        );
        assert_eq!(policy.using.is_some(), has_using);
        assert_eq!(policy.with_check.is_some(), has_with_check);
        for predicate in [policy.using.as_ref(), policy.with_check.as_ref()]
            .into_iter()
            .flatten()
        {
            let expression = predicate.to_string();
            assert!(expression.contains("tenant_id"));
            assert!(expression.contains("pg_catalog.current_setting"));
            assert!(expression.contains("'bioworld.tenant_id'"));
            assert!(expression.contains("true"));
            assert!(expression.contains("NULLIF"));
            assert!(expression.contains("''"));
        }
    }

    let uppercase = normalized.to_ascii_uppercase();
    for forbidden in [
        "CREATE ROLE",
        "CREATE USER",
        "ALTER ROLE",
        "SET ROLE",
        "PASSWORD",
        " LOGIN",
        "BIOWORLD_OWNER",
        "BIOWORLD_MIGRATOR",
        "BIOWORLD_WRITER",
    ] {
        assert!(
            !uppercase.contains(forbidden),
            "schema migrations must not provision runtime roles: {forbidden}"
        );
    }
    assert!(!statements.iter().any(|statement| matches!(
        statement,
        Statement::CreateRole(_)
            | Statement::CreateUser(_)
            | Statement::AlterRole { .. }
            | Statement::Set(SetStatement::SetRole { .. })
            | Statement::Grant(_)
    )));
    let revokes = statements
        .iter()
        .filter_map(|statement| match statement {
            Statement::Revoke(revoke) => Some(revoke),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(revokes.len(), 3);
    assert!(
        revokes
            .iter()
            .all(|revoke| revoke.grantees.iter().all(|grantee| {
                grantee.grantee_type == GranteesType::Public && grantee.name.is_none()
            }))
    );
}
