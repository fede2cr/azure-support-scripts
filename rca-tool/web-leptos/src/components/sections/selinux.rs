use leptos::prelude::*;
use serde_json::Value;

use super::helpers::*;

/// SELinux mandatory access control: configured/current mode plus AVC and
/// SELinux audit errors.
#[component]
pub fn SelinuxSection(data: Value) -> impl IntoView {
    let selinux = data.get("selinux").cloned().unwrap_or(Value::Null);
    let selinux_errors = data.get("selinuxErrors").cloned().unwrap_or(Value::Null);

    let has_selinux = json_bool(&selinux, "found");
    let errors = json_array(&selinux_errors, "events");
    let has_selinux_errors = json_bool(&selinux_errors, "found") || !errors.is_empty();

    if !has_selinux && !has_selinux_errors {
        return view! {}.into_any();
    }

    let warnings = json_array(&selinux, "warnings");
    let recommendations = json_array(&selinux, "recommendations");
    let section_class = if !warnings.is_empty() || has_selinux_errors {
        "warning-block"
    } else {
        "content-details"
    };

    let config_mode = dash_if_empty(json_str(&selinux, "configMode"));
    let current_mode = dash_if_empty(json_str(&selinux, "currentMode"));
    let source_path = json_str(&selinux, "sourcePath");
    let current_line = selinux.get("currentSourceLine").and_then(Value::as_u64);
    let config_line = selinux.get("configSourceLine").and_then(Value::as_u64);
    let status_source = match (source_path.is_empty(), current_line.or(config_line)) {
        (true, _) => "-".to_string(),
        (false, Some(line)) => format!("{source_path}:{line}"),
        (false, None) => source_path,
    };

    view! {
        <Section title="SELinux" class=section_class open=true>
            <div class="subsection">
                <p class="subsection-title">"SELinux:"</p>
                <KvTable>
                    <KvRow label="Current mode" value=current_mode/>
                    <KvRow label="Mode from config" value=config_mode/>
                    <KvRow label="Status source" value=status_source/>
                </KvTable>
                {render_findings(
                    &format!("SELinux Warnings ({})", warnings.len()),
                    "warning-block",
                    warnings,
                )}
                {render_findings("Recommendations", "info-block", recommendations)}
                {render_selinux_errors(errors)}
            </div>
        </Section>
    }
    .into_any()
}

fn render_selinux_errors(errors: Vec<Value>) -> Option<AnyView> {
    if errors.is_empty() {
        return None;
    }
    Some(
        view! {
            <div class="warning-block">
                <p><strong>{format!("SELinux Errors ({})", errors.len())}</strong></p>
                <div class="table-wrapper">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>"Source"</th>
                                <th>"Type"</th>
                                <th>"Command"</th>
                                <th>"Permissions"</th>
                                <th>"Audit record"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {errors
                                .iter()
                                .map(|event| {
                                    let source_path = json_str(event, "sourcePath");
                                    let source_line = event
                                        .get("sourceLine")
                                        .or_else(|| event.get("lineNumber"))
                                        .and_then(Value::as_u64);
                                    let source = match source_line {
                                        Some(line) => format!("{source_path}:{line}"),
                                        None => source_path,
                                    };
                                    let permissions = json_array(event, "permissions")
                                        .iter()
                                        .filter_map(Value::as_str)
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    view! {
                                        <tr>
                                            <td><code>{source}</code></td>
                                            <td>{json_str(event, "eventType")}</td>
                                            <td>{dash_if_empty(json_str(event, "command"))}</td>
                                            <td>{dash_if_empty(permissions)}</td>
                                            <td><code>{json_str(event, "rawLine")}</code></td>
                                        </tr>
                                    }
                                })
                                .collect::<Vec<_>>()}
                        </tbody>
                    </table>
                </div>
            </div>
        }
        .into_any(),
    )
}
