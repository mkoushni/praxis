// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Load-time checks for response rules whose payload is unavailable.

use ppe::{
    praxis_policy_apl_core::{
        parser::compile_policy_block_value,
        rules::{Condition, Effect, Expression},
    },
    praxis_policy_core::{
        cmf::constants::{ENTITY_PROMPT, ENTITY_RESOURCE},
        config::{PolicyConfig, RouteEntry, route_bundle_names, route_entity_identity},
    },
};
use serde_yaml::Value;

use crate::FilterError;

/// Reject prompt/resource field pipelines until their result is projected.
pub(super) fn ensure_supported_entity_results(yaml: &str, config: &PolicyConfig) -> Result<(), FilterError> {
    let document: Value = serde_yaml::from_str(yaml)
        .map_err(|error| -> FilterError { format!("policy: cannot validate response field rules: {error}").into() })?;
    let mut unsupported = Vec::new();

    for (index, route) in config.routes.iter().enumerate() {
        let Some((entity, _)) =
            route_entity_identity(route).filter(|(entity, _)| matches!(*entity, ENTITY_PROMPT | ENTITY_RESOURCE))
        else {
            continue;
        };
        unsupported.extend(result_sources(&document, route, index, entity));
    }

    unsupported.sort();
    unsupported.dedup();
    if unsupported.is_empty() {
        return Ok(());
    }

    Err(format!(
        "policy: {} declares `result:` field rules for prompt/resource routes, but their result \
         projection is unavailable (praxis-proxy/policy#75, praxis-proxy/praxis#1330). Remove those \
         field rules; attribute-only `post_invocation` rules remain supported.",
        unsupported.join(", ")
    )
    .into())
}

/// Build a policy document whose post-invocation rules need no response body.
pub(super) fn metadata_only_policy(yaml: &str) -> Result<Option<String>, FilterError> {
    let mut document: Value = serde_yaml::from_str(yaml).map_err(|error| -> FilterError {
        format!("policy: cannot prepare metadata-only response rules: {error}").into()
    })?;
    let retained = filter_document(&mut document)?;
    if retained == 0 {
        return Ok(None);
    }
    serde_yaml::to_string(&document)
        .map(Some)
        .map_err(|error| format!("policy: cannot render metadata-only response rules: {error}").into())
}

/// Filter every policy layer that can contribute to an effective route.
fn filter_document(document: &mut Value) -> Result<usize, FilterError> {
    let mut retained = 0;
    let Some(root) = document.as_mapping_mut() else {
        return Ok(retained);
    };
    if let Some(global) = root.get_mut("global") {
        retained = retained.saturating_add(filter_policy_block(global, "global")?);
        if let Some(defaults) = global.get_mut("defaults").and_then(Value::as_mapping_mut) {
            for (entity, block) in defaults {
                retained = retained.saturating_add(filter_policy_block(
                    block,
                    &format!("global.defaults.{}", key_name(entity)),
                )?);
            }
        }
    }
    if let Some(groups) = root.get_mut("groups").and_then(Value::as_mapping_mut) {
        for (name, block) in groups {
            retained = retained.saturating_add(filter_policy_block(block, &format!("groups.{}", key_name(name)))?);
        }
    }
    if let Some(routes) = root.get_mut("routes").and_then(Value::as_sequence_mut) {
        for (index, block) in routes.iter_mut().enumerate() {
            retained = retained.saturating_add(filter_policy_block(block, &format!("routes[{index}]"))?);
        }
    }
    Ok(retained)
}

/// Drop result pipelines and response-content-dependent post steps from one layer.
fn filter_policy_block(block: &mut Value, source: &str) -> Result<usize, FilterError> {
    let Some(mapping) = block.as_mapping_mut() else {
        return Ok(0);
    };
    mapping.remove("result");
    let Some(authorization) = mapping.get_mut("authorization").and_then(Value::as_mapping_mut) else {
        return Ok(0);
    };
    let retained = authorization
        .get("post_invocation")
        .and_then(Value::as_sequence)
        .map(|steps| filter_post_steps(steps, source))
        .transpose()?
        .unwrap_or_default();
    if retained.is_empty() {
        authorization.remove("post_invocation");
    } else {
        authorization.insert(
            Value::String("post_invocation".to_owned()),
            Value::Sequence(retained.clone()),
        );
    }
    let pre_empty = authorization
        .get("pre_invocation")
        .and_then(Value::as_sequence)
        .is_none_or(Vec::is_empty);
    if pre_empty && retained.is_empty() {
        mapping.remove("authorization");
    }
    Ok(retained.len())
}

/// Compile each declared step and retain only effects independent of response content.
fn filter_post_steps(steps: &[Value], source: &str) -> Result<Vec<Value>, FilterError> {
    steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let block = Value::Mapping(serde_yaml::Mapping::from_iter([(
                Value::String("authorization".to_owned()),
                Value::Mapping(serde_yaml::Mapping::from_iter([(
                    Value::String("post_invocation".to_owned()),
                    Value::Sequence(vec![step.clone()]),
                )])),
            )]));
            let compiled = compile_policy_block_value(source, &block).map_err(|error| -> FilterError {
                format!("policy: cannot classify {source}[{index}]: {error}").into()
            })?;
            Ok((!compiled.post_invocation.iter().any(effect_reads_response_content)).then(|| step.clone()))
        })
        .filter_map(|result: Result<Option<Value>, FilterError>| result.transpose())
        .collect()
}

/// Whether an effect reads response content unavailable on metadata-only dispatch.
fn effect_reads_response_content(effect: &Effect) -> bool {
    match effect {
        Effect::FieldOp { path, .. } => content_key(path),
        Effect::When { condition, body, .. } => {
            expression_reads_response_content(condition) || body.iter().any(effect_reads_response_content)
        },
        Effect::Sequential(effects) | Effect::Parallel(effects) => effects.iter().any(effect_reads_response_content),
        Effect::Pdp {
            call,
            on_allow,
            on_deny,
        } => {
            yaml_reads_response_content(&call.args)
                || on_allow.iter().any(effect_reads_response_content)
                || on_deny.iter().any(effect_reads_response_content)
        },
        Effect::Allow
        | Effect::Deny { .. }
        | Effect::Plugin { .. }
        | Effect::Delegate(_)
        | Effect::Elicit(_)
        | Effect::Taint { .. }
        | Effect::Restrict { .. } => false,
    }
}

/// Whether an expression references completion or result fields.
fn expression_reads_response_content(expression: &Expression) -> bool {
    match expression {
        Expression::Condition(condition) => condition_reads_response_content(condition),
        Expression::And(parts) | Expression::Or(parts) => parts.iter().any(expression_reads_response_content),
        Expression::Not(inner) => expression_reads_response_content(inner),
        Expression::Always => false,
    }
}

/// Whether a leaf condition references completion or result fields.
fn condition_reads_response_content(condition: &Condition) -> bool {
    match condition {
        Condition::Comparison { key, .. }
        | Condition::IsTrue { key }
        | Condition::IsFalse { key }
        | Condition::Exists { key } => content_key(key),
        Condition::InSet { value_key, set_key, .. } => content_key(value_key) || content_key(set_key),
    }
}

/// Whether opaque PDP arguments contain a response-content attribute reference.
fn yaml_reads_response_content(value: &Value) -> bool {
    match value {
        Value::String(value) => value
            .split(|character: char| !character.is_alphanumeric() && character != '_' && character != '.')
            .any(content_key),
        Value::Sequence(values) => values.iter().any(yaml_reads_response_content),
        Value::Mapping(values) => values
            .iter()
            .any(|(key, value)| yaml_reads_response_content(key) || yaml_reads_response_content(value)),
        Value::Tagged(tagged) => yaml_reads_response_content(&tagged.value),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// Whether a policy attribute belongs to the unavailable response body.
fn content_key(key: &str) -> bool {
    ["completion", "result"]
        .iter()
        .any(|prefix| key == *prefix || key.strip_prefix(prefix).is_some_and(|suffix| suffix.starts_with('.')))
}

/// Render a YAML mapping key for diagnostics.
fn key_name(value: &Value) -> String {
    value.as_str().unwrap_or("<non-string>").to_owned()
}

/// Locate direct and inherited field rules for one prompt/resource route.
fn result_sources(document: &Value, route: &RouteEntry, index: usize, entity: &str) -> Vec<String> {
    let global = document.get("global");
    let defaults = global
        .and_then(|block| block.get("defaults"))
        .and_then(|block| block.get(entity));
    let own = document.get("routes").and_then(|routes| routes.get(index));
    let groups = document.get("groups");

    [
        ("global".to_owned(), global),
        (format!("global.defaults.{entity}"), defaults),
        (format!("routes[{index}] ({entity})"), own),
    ]
    .into_iter()
    .chain(route_bundle_names(route).into_iter().map(|name| {
        let block = groups.and_then(|groups| groups.get(&name));
        (format!("groups.{name}"), block)
    }))
    .filter(|(_, block)| {
        block
            .and_then(|block| block.get("result"))
            .and_then(Value::as_mapping)
            .is_some_and(|fields| !fields.is_empty())
    })
    .map(|(source, _)| source)
    .collect()
}
