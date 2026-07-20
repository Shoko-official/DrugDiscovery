use std::{collections::BTreeMap, fs, path::PathBuf};

use sqlparser::{
    ast::{
        Action, AlterColumnOperation, AlterTableOperation, DataType, ExactNumberInfo,
        FunctionReturnType, GrantObjects, GranteesType, Privileges, Statement, TableConstraint,
        TriggerEvent, TriggerObject, TriggerObjectKind, TriggerPeriod,
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
        Parser::parse_sql(&PostgreSqlDialect {}, &sql)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
    }
}

#[test]
fn decision_event_migration_enforces_the_storage_contract() {
    let statements = parse_migration("0002_decision_event_contract.sql");

    assert!(matches!(
        statements.first(),
        Some(Statement::StartTransaction { .. })
    ));
    assert!(matches!(statements.last(), Some(Statement::Commit { .. })));

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
