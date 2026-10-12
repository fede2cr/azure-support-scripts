use leptos::prelude::*;
use serde_json::Value;

use super::helpers::*;

/// OS tuning checks ported from the SAP-on-Azure QualityCheck utility: tuned
/// profile, swap space, and the fstrim timer.
#[component]
pub fn OsTuningSection(data: Value) -> impl IntoView {
    let tuned = data.get("tunedProfile").cloned().unwrap_or(Value::Null);
    let swap = data.get("swapSpace").cloned().unwrap_or(Value::Null);
    let fstrim = data.get("fstrim").cloned().unwrap_or(Value::Null);

    let has_tuned = json_bool(&tuned, "found");
    let has_swap = json_bool(&swap, "found");
    let has_fstrim = json_bool(&fstrim, "found");

    if !has_tuned && !has_swap && !has_fstrim {
        return view! {}.into_any();
    }

    let has_warnings = !json_array(&tuned, "warnings").is_empty()
        || !json_array(&swap, "warnings").is_empty()
        || !json_array(&fstrim, "warnings").is_empty();

    let section_class = if has_warnings {
        "warning-block"
    } else {
        "content-details"
    };

    view! {
        <Section title="OS Tuning" class=section_class open=true>
            {has_tuned.then(|| render_tuned_profile(&tuned))}
            {has_swap.then(|| render_swap(&swap))}
            {has_fstrim.then(|| render_fstrim(&fstrim))}
        </Section>
    }
    .into_any()
}

fn render_tuned_profile(tuned: &Value) -> AnyView {
    let active = dash_if_empty(json_str(tuned, "activeProfile"));
    let warnings = json_array(tuned, "warnings");
    let recommendations = json_array(tuned, "recommendations");
    view! {
        <div class="subsection">
            <p class="subsection-title">"Tuned Profile:"</p>
            <KvTable>
                <KvRow label="Active profile" value=active/>
            </KvTable>
            {render_findings(
                &format!("Tuned Warnings ({})", warnings.len()),
                "warning-block",
                warnings,
            )}
            {render_findings("Recommendations", "info-block", recommendations)}
        </div>
    }
    .into_any()
}

fn render_swap(swap: &Value) -> AnyView {
    let total_kb = swap.get("swapTotalKb").and_then(|v| v.as_i64());
    let free_kb = swap.get("swapFreeKb").and_then(|v| v.as_i64());
    let warnings = json_array(swap, "warnings");
    let total_display = match total_kb {
        Some(kb) if kb >= 0 => format_bytes((kb * 1024) as f64),
        _ => "-".to_string(),
    };
    let free_display = match free_kb {
        Some(kb) if kb >= 0 => format_bytes((kb * 1024) as f64),
        _ => "-".to_string(),
    };
    view! {
        <div class="subsection">
            <p class="subsection-title">"Swap Space:"</p>
            <KvTable>
                <KvRow label="Swap total" value=total_display/>
                <KvRow label="Swap free" value=free_display/>
            </KvTable>
            {render_findings(
                &format!("Swap Warnings ({})", warnings.len()),
                "warning-block",
                warnings,
            )}
        </div>
    }
    .into_any()
}

fn render_fstrim(fstrim: &Value) -> AnyView {
    let state = dash_if_empty(json_str(fstrim, "timerState"));
    let enabled = json_bool(fstrim, "timerEnabled");
    let warnings = json_array(fstrim, "warnings");
    view! {
        <div class="subsection">
            <p class="subsection-title">"fstrim Timer:"</p>
            <KvTable>
                <KvRow label="Timer state" value=state/>
                <KvRow
                    label="Periodic trim enabled"
                    value=if enabled { "Yes".to_string() } else { "No".to_string() }
                />
            </KvTable>
            {render_findings(
                &format!("fstrim Warnings ({})", warnings.len()),
                "warning-block",
                warnings,
            )}
        </div>
    }
    .into_any()
}
