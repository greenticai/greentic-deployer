//! Bootstrap-time IAM rules-pack emitter for the AWS-ECS env-pack (C3).
//!
//! Renders a minimum-privilege IAM role + inline policy as a Terraform
//! module the customer's admin can review and `tofu apply` / `terraform
//! apply` against their own state backend. Two files land under
//! `<env_root>/rules/greentic.deployer.aws-ecs/`:
//!
//! - `aws-min-iam.tf` — `aws_iam_role` + `aws_iam_role_policy` (inline) +
//!   `output "role_arn"` so downstream automation can capture the ARN.
//! - `README.md` — operator-facing apply instructions.
//!
//! The customer is in the loop, by design: an admin reviews the HCL,
//! decides whether the trust policy and action surface are acceptable for
//! their account, then applies it. Greentic never executes Terraform
//! against the customer's account in C3 — that's Phase D D-AWS-1, when
//! the deployer runs against a credentialed STS session.
//!
//! ## Allowed actions
//!
//! Sourced from
//! [`super::credentials::VALIDATED_IAM_VERBS`](crate::env_packs::aws::credentials::VALIDATED_IAM_VERBS)
//! — the same list `validate` simulates. The role the customer creates
//! and the verbs the validator probes against an existing principal are
//! the same set, so the bootstrap-then-validate loop converges (apply
//! the rules pack → bind the role's ARN to the env's credentials_ref →
//! re-run requirements → green).
//!
//! ## Trust principal
//!
//! `admin_identity_hint` from `BootstrapInput.admin.profile()` lands in
//! the `assume_role_policy` so the operator sees who can assume the
//! generated role. We accept either a full ARN (`arn:aws:iam::…`) or a
//! named profile / IAM user name (which the customer's admin substitutes
//! at apply time). When the hint is a bare ARN we render it inline; when
//! it isn't, we substitute it into a placeholder the admin replaces.

use crate::credentials::{RulesPack, RulesPackEntry};

/// Input shape for [`render_min_iam_rules_pack`]. Borrowed; no heap cost.
pub struct IamRulesPackInput<'a> {
    /// Env this pack is scoped to. Used in the role name + tags so the
    /// emitted resources are distinguishable per-env if a customer runs
    /// multiple Greentic envs in one AWS account.
    pub env_id: &'a str,
    /// Operator-supplied admin identity for the role's trust policy. May
    /// be a full IAM ARN or a free-form hint the admin fills in at apply.
    pub admin_identity_hint: &'a str,
    /// IAM verbs the role's inline policy will allow. Mirrors the
    /// validate-time verb list 1:1.
    pub allowed_actions: &'a [&'static str],
}

/// Render the rules pack. Pure function — no I/O. The writer
/// (`crate::credentials::write_rules_pack`) lands these on disk inside
/// the bootstrap flock.
pub fn render_min_iam_rules_pack(input: &IamRulesPackInput<'_>) -> RulesPack {
    let tf = render_terraform(input);
    let readme = render_readme(input);
    RulesPack {
        entries: vec![
            RulesPackEntry {
                filename: "aws-min-iam.tf".into(),
                content: tf,
                description: Some(format!(
                    "Minimum-privilege IAM role + inline policy for Greentic env `{}` \
                     (ECS rollout surface).",
                    input.env_id
                )),
            },
            RulesPackEntry {
                filename: "README.md".into(),
                content: readme,
                description: Some(
                    "Apply instructions for the AWS-ECS bootstrap rules pack.".into(),
                ),
            },
        ],
    }
}

/// Sensitivity bucket for IAM action scoping in the rendered policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ActionBucket {
    /// `sts:*` and `iam:Simulate*` — read-only, safe at `Resource = "*"`.
    ReadOnly,
    /// `ecs:*` — ECS rollout, scoped to cluster/service/task-set ARN.
    Ecs,
    /// `ecs:Register/DeregisterTaskDefinition` — no resource-level scoping;
    /// Resource = "*".
    EcsTaskDefinition,
    /// `ecr:*` — image push, scoped to repo ARN.
    Ecr,
    /// `elasticloadbalancing:Describe*` — no resource-level scoping;
    /// Resource = "*".
    AlbReadOnly,
    /// `elasticloadbalancing:*` — ALB mutation, scoped to listener ARN.
    Alb,
    /// `iam:PassRole` — privilege-sensitive, scoped + conditioned.
    PassRole,
    /// Unrecognized action — falls to a review bucket.
    Unrecognized,
}

fn classify_action(action: &str) -> ActionBucket {
    if action == "iam:PassRole" {
        return ActionBucket::PassRole;
    }
    if action.starts_with("sts:") || action.starts_with("iam:Simulate") {
        return ActionBucket::ReadOnly;
    }
    if action == "ecs:RegisterTaskDefinition" || action == "ecs:DeregisterTaskDefinition" {
        return ActionBucket::EcsTaskDefinition;
    }
    if action.starts_with("ecs:") {
        return ActionBucket::Ecs;
    }
    if action.starts_with("ecr:") {
        return ActionBucket::Ecr;
    }
    if action.starts_with("elasticloadbalancing:Describe") {
        return ActionBucket::AlbReadOnly;
    }
    if action.starts_with("elasticloadbalancing:") {
        return ActionBucket::Alb;
    }
    ActionBucket::Unrecognized
}

/// HCL Condition block appended to the `iam:PassRole` statement so the
/// generated role can only pass roles to ECS tasks. Hoisted to a `const`
/// so `BUCKET_SPECS` can carry a `Some(&'static str)` reference.
const PASS_ROLE_CONDITION: &str = "\
\n          Condition = {\
\n            StringEquals = {\
\n              \"iam:PassedToService\" = \"ecs-tasks.amazonaws.com\"\
\n            }\
\n          }\n";

/// Static descriptor for one rendered policy statement.
///
/// The table order is the emission order — readers see the same shape in
/// `BUCKET_SPECS` that they see in the rendered HCL, and adding a future
/// bucket is a single table entry rather than copy-pasting an if-block.
struct BucketSpec {
    bucket: ActionBucket,
    comment: &'static str,
    resource: &'static str,
    extra: Option<&'static str>,
}

/// Statement-emission order. Mirrors the audit narrative in the rendered
/// HCL: read-only verbs first (least sensitive), then service-scoped
/// verbs, then `iam:PassRole` (conditioned), then unrecognized (flagged).
const BUCKET_SPECS: &[BucketSpec] = &[
    BucketSpec {
        bucket: ActionBucket::ReadOnly,
        comment: "Read-only validation surface — safe at Resource = \"*\".",
        resource: "*",
        extra: None,
    },
    BucketSpec {
        bucket: ActionBucket::Ecs,
        comment: "ECS rollout — admin scopes to cluster/service/task-set ARNs at apply.",
        resource: "<REPLACE_WITH_ECS_RESOURCE_ARNS>",
        extra: None,
    },
    BucketSpec {
        bucket: ActionBucket::EcsTaskDefinition,
        comment: "ECS task-definition lifecycle — no resource-level scoping; Resource must be \"*\".",
        resource: "*",
        extra: None,
    },
    BucketSpec {
        bucket: ActionBucket::Ecr,
        comment: "ECR image push — admin scopes to repo ARN.",
        resource: "<REPLACE_WITH_ECR_REPO_ARNS>",
        extra: None,
    },
    BucketSpec {
        bucket: ActionBucket::AlbReadOnly,
        comment: "ELB describe — no resource-level scoping; Resource = \"*\".",
        resource: "*",
        extra: None,
    },
    BucketSpec {
        bucket: ActionBucket::Alb,
        comment: "ALB listener mutation — admin scopes to listener ARN.",
        resource: "<REPLACE_WITH_ALB_LISTENER_ARNS>",
        extra: None,
    },
    BucketSpec {
        bucket: ActionBucket::PassRole,
        comment: "iam:PassRole — only for the ECS task-execution role, scoped + conditioned.",
        resource: "<REPLACE_WITH_ECS_TASK_ROLE_ARN>",
        extra: Some(PASS_ROLE_CONDITION),
    },
    BucketSpec {
        bucket: ActionBucket::Unrecognized,
        comment: "UNRECOGNIZED ACTION — review before applying.",
        resource: "*",
        extra: None,
    },
];

/// Render one HCL policy statement block. `extra_fields` carries optional
/// Condition blocks or comments appended after `Resource`. Pre-sizes the
/// buffer + uses `write!` so the per-statement render is zero-extra-alloc
/// (the only heap touch is the returned `String` itself).
fn render_statement(
    comment: &str,
    actions: &[&str],
    resource: &str,
    extra_fields: Option<&str>,
) -> String {
    use std::fmt::Write as _;
    let indent = "        ";
    let mut s = String::with_capacity(256);
    let _ = writeln!(s, "{indent}# {comment}");
    let _ = writeln!(s, "{indent}{{");
    let _ = writeln!(s, "{indent}  Effect = \"Allow\"");
    if let [single] = actions {
        let _ = writeln!(s, "{indent}  Action = \"{single}\"");
    } else {
        let _ = writeln!(s, "{indent}  Action = [");
        for a in actions {
            let _ = writeln!(s, "{indent}    \"{a}\",");
        }
        let _ = writeln!(s, "{indent}  ]");
    }
    let _ = writeln!(s, "{indent}  Resource = \"{resource}\"");
    if let Some(extra) = extra_fields {
        s.push_str(extra);
    }
    let _ = write!(s, "{indent}}}");
    s
}

fn render_terraform(input: &IamRulesPackInput<'_>) -> String {
    // Bucket actions by sensitivity in one pass; emit statements in
    // BUCKET_SPECS order (an empty bucket emits nothing). HashMap because
    // iteration order is governed by the static table, not the map.
    let mut buckets: std::collections::HashMap<ActionBucket, Vec<&str>> =
        std::collections::HashMap::with_capacity(BUCKET_SPECS.len());
    for action in input.allowed_actions {
        buckets
            .entry(classify_action(action))
            .or_default()
            .push(action);
    }

    let statements: Vec<String> = BUCKET_SPECS
        .iter()
        .filter_map(|spec| {
            buckets
                .get(&spec.bucket)
                .filter(|actions| !actions.is_empty())
                .map(|actions| render_statement(spec.comment, actions, spec.resource, spec.extra))
        })
        .collect();

    let statements_hcl = statements.join(",\n");

    // Trust principal rendering: if the hint already looks like an ARN we
    // inline it; otherwise we drop a placeholder the admin substitutes.
    let trust_principal = if looks_like_arn(input.admin_identity_hint) {
        format!("\"{}\"", input.admin_identity_hint)
    } else {
        format!(
            "\"<REPLACE_WITH_ADMIN_ARN_FOR_{}>\" # operator hint: `{}`",
            // Uppercase, dash-stripped env_id for placeholder readability;
            // resolved by the admin at apply.
            input.env_id.to_uppercase().replace('-', "_"),
            input.admin_identity_hint,
        )
    };

    format!(
        r#"# Greentic env-pack bootstrap — AWS-ECS deployer credentials (C3).
#
# Apply this with `tofu apply` (preferred) or `terraform apply` against the
# AWS account that will host the Greentic env `{env_id}`. The IAM role
# created here is the principal Greentic uses at deploy time; the inline
# policy is the minimum set of actions exercised by the ECS rollout
# surface (validated against this exact list by `gtc op credentials
# requirements {env_id}`).
#
# IMPORTANT: Resource placeholders (`<REPLACE_WITH_*>`) must be replaced
# with the actual ARNs from your AWS account before applying:
#
#   <REPLACE_WITH_ECS_RESOURCE_ARNS>  — e.g. arn:aws:ecs:<region>:<account>:service/<cluster>/greentic-*
#   <REPLACE_WITH_ECR_REPO_ARNS>      — e.g. arn:aws:ecr:<region>:<account>:repository/greentic-*
#   <REPLACE_WITH_ALB_LISTENER_ARNS>  — e.g. arn:aws:elasticloadbalancing:<region>:<account>:listener/app/<lb>/<id>/<id>
#   <REPLACE_WITH_ECS_TASK_ROLE_ARN>  — e.g. arn:aws:iam::<account>:role/greentic-{env_id}-task-execution
#
# Trust principal is rendered from the operator-supplied admin hint:
#   `{admin_hint}`
# If your IaC pipeline runs as a different IAM principal, edit the
# `assume_role_policy` block below before applying.
#
# Generated by greentic-deployer; safe to commit to source control.

resource "aws_iam_role" "greentic_{env_id_safe}" {{
  name = "greentic-{env_id}-deployer"

  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {{
          AWS = {trust_principal}
        }}
      }}
    ]
  }})

  tags = {{
    "greentic.ai/env"     = "{env_id}"
    "greentic.ai/managed" = "true"
  }}
}}

resource "aws_iam_role_policy" "greentic_{env_id_safe}_min" {{
  name = "greentic-{env_id}-min"
  role = aws_iam_role.greentic_{env_id_safe}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
{statements_hcl}
    ]
  }})
}}

output "role_arn" {{
  description = "ARN of the Greentic deployer role for env {env_id}. Bind this to the env's credentials_ref."
  value       = aws_iam_role.greentic_{env_id_safe}.arn
}}
"#,
        env_id = input.env_id,
        // Replace dashes with underscores for Terraform resource name
        // legality (resource names accept [a-zA-Z0-9_-] but `-` requires
        // quoting in some downstream contexts; underscored is safer).
        env_id_safe = input.env_id.replace('-', "_"),
        admin_hint = input.admin_identity_hint,
        trust_principal = trust_principal,
        statements_hcl = statements_hcl,
    )
}

fn render_readme(input: &IamRulesPackInput<'_>) -> String {
    format!(
        r#"# AWS-ECS bootstrap rules pack — env `{env_id}`

Generated by `gtc op credentials bootstrap {env_id}` for the
`greentic.deployer.aws-ecs` env-pack (C3 stub).

## What this is

A minimum-privilege IAM role + inline policy your AWS admin reviews and
applies into the AWS account that will host Greentic env `{env_id}`. The
inline policy grants only the actions Greentic's ECS rollout surface
exercises:

{action_bullets}

The policy is split into multiple statements by sensitivity:

- **Read-only** (`sts:GetCallerIdentity`, `iam:SimulatePrincipalPolicy`)
  — `Resource = "*"` is safe; these are validation-only.
- **ECS rollout** (scopable `ecs:*` verbs) — replace
  `<REPLACE_WITH_ECS_RESOURCE_ARNS>` with your cluster/service/task-set
  ARNs, e.g.
  `arn:aws:ecs:<region>:<account>:service/<cluster>/greentic-*`.
- **ECS task-definition lifecycle** (`ecs:RegisterTaskDefinition`,
  `ecs:DeregisterTaskDefinition`) — granted at `Resource = "*"` because
  AWS provides no resource-level scoping for these actions.
- **ECR** (`ecr:PutImage`) — replace `<REPLACE_WITH_ECR_REPO_ARNS>` with
  your repository ARN, e.g.
  `arn:aws:ecr:<region>:<account>:repository/greentic-*`.
- **ELB describe** (`elasticloadbalancing:DescribeTargetGroups`) —
  granted at `Resource = "*"` because AWS provides no resource-level
  scoping for describe actions.
- **ALB listener mutation** (`elasticloadbalancing:ModifyListener`) —
  replace `<REPLACE_WITH_ALB_LISTENER_ARNS>` with your listener ARN.
- **iam:PassRole** — replace `<REPLACE_WITH_ECS_TASK_ROLE_ARN>` with the
  ARN of the ECS task-execution role, e.g.
  `arn:aws:iam::<account>:role/greentic-{env_id}-task-execution`.
  Conditioned on `iam:PassedToService = ecs-tasks.amazonaws.com`.

## How to apply

1. Review `aws-min-iam.tf`. Replace every `<REPLACE_WITH_*>` placeholder
   with the actual ARNs from your AWS account. The trust principal is
   currently:

   ```
   {admin_hint}
   ```

   Edit the `assume_role_policy` if you want a different IAM principal
   (role / user / federated identity) to be able to assume this role.

2. From this directory, with AWS admin credentials in your shell:

   ```sh
   tofu init && tofu apply
   # or: terraform init && terraform apply
   ```

   Use your own remote state backend (S3 + DynamoDB, Terraform Cloud,
   ...). Greentic does not manage Terraform state for you.

3. Capture the `role_arn` output:

   ```sh
   tofu output -raw role_arn
   # arn:aws:iam::111122223333:role/greentic-{env_id}-deployer
   ```

4. Bind the ARN to env `{env_id}`'s credentials backend:

   ```sh
   gtc op credentials rotate {env_id} --provided-credentials-ref \
     "secret://{env_id}/aws-ecs/role-arn"
   ```

   (Phase D wires the live secret-backend write; until then, see the
   `requires_credentials_material = true` note in `gtc op env doctor
   {env_id}` output.)

5. Re-run requirements:

   ```sh
   gtc op credentials requirements {env_id}
   ```

   All capabilities (`{sts_cap}` + the IAM verbs above) must pass
   before `gtc op deploy {env_id}` is honored.

## What this does NOT do

C3 is the credentials stub. Phase D D-AWS-1 adds the rest of the ECS
provisioning Terraform (VPC, ECR repository, ALB, ECS cluster, task
definitions). For now this pack only creates the IAM role Greentic
assumes at deploy time.
"#,
        env_id = input.env_id,
        admin_hint = input.admin_identity_hint,
        sts_cap = "aws.sts.caller-identity",
        action_bullets = input
            .allowed_actions
            .iter()
            .map(|a| format!("- `{a}`"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Cheap heuristic: an IAM ARN starts with `arn:` and contains `iam`. We
/// do NOT do strict structural validation here — a malformed ARN that
/// passes the prefix check is on the operator (the customer's admin
/// reviews the HCL before apply, so the cost of a render-time mistake is
/// "the admin sees a broken trust policy", not "Greentic silently grants
/// the wrong principal").
fn looks_like_arn(s: &str) -> bool {
    s.starts_with("arn:") && s.contains(":iam:")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(env_id: &'a str, admin_hint: &'a str) -> IamRulesPackInput<'a> {
        IamRulesPackInput {
            env_id,
            admin_identity_hint: admin_hint,
            allowed_actions: &["sts:GetCallerIdentity", "ecs:CreateService"],
        }
    }

    #[test]
    fn renders_two_entries_tf_and_readme() {
        let pack = render_min_iam_rules_pack(&input(
            "prod-eu",
            "arn:aws:iam::111122223333:role/customer-admin",
        ));
        assert_eq!(pack.entries.len(), 2);
        let filenames: Vec<&str> = pack.entries.iter().map(|e| e.filename.as_str()).collect();
        assert!(filenames.contains(&"aws-min-iam.tf"));
        assert!(filenames.contains(&"README.md"));
    }

    #[test]
    fn tf_inlines_arn_when_admin_hint_is_an_arn() {
        let pack = render_min_iam_rules_pack(&input(
            "prod-eu",
            "arn:aws:iam::111122223333:role/customer-admin",
        ));
        let tf = pack
            .entries
            .iter()
            .find(|e| e.filename == "aws-min-iam.tf")
            .unwrap();
        assert!(
            tf.content
                .contains("\"arn:aws:iam::111122223333:role/customer-admin\""),
            "tf should inline the ARN in the trust policy"
        );
        // No placeholder for ARN-shaped hints.
        assert!(
            !tf.content.contains("<REPLACE_WITH_ADMIN_ARN_FOR_"),
            "ARN hint should not produce a placeholder"
        );
    }

    #[test]
    fn tf_emits_placeholder_when_admin_hint_is_not_an_arn() {
        let pack = render_min_iam_rules_pack(&input("stg-aws", "customer-admin-profile"));
        let tf = pack
            .entries
            .iter()
            .find(|e| e.filename == "aws-min-iam.tf")
            .unwrap();
        assert!(
            tf.content.contains("<REPLACE_WITH_ADMIN_ARN_FOR_STG_AWS>"),
            "non-ARN hint should produce an uppercase placeholder; content:\n{}",
            tf.content
        );
        assert!(
            tf.content.contains("customer-admin-profile"),
            "non-ARN hint should appear as an operator comment; content:\n{}",
            tf.content
        );
    }

    #[test]
    fn tf_inlines_every_allowed_action() {
        let input = IamRulesPackInput {
            env_id: "prod-eu",
            admin_identity_hint: "arn:aws:iam::111122223333:role/x",
            allowed_actions: &[
                "sts:GetCallerIdentity",
                "iam:SimulatePrincipalPolicy",
                "ecs:CreateService",
                "ecs:UpdateService",
                "ecs:CreateTaskSet",
                "ecr:PutImage",
                "elasticloadbalancing:ModifyListener",
                "iam:PassRole",
            ],
        };
        let pack = render_min_iam_rules_pack(&input);
        let tf = pack
            .entries
            .iter()
            .find(|e| e.filename == "aws-min-iam.tf")
            .unwrap();
        for action in input.allowed_actions {
            assert!(
                tf.content.contains(&format!("\"{action}\"")),
                "tf must contain action `{action}`; content:\n{}",
                tf.content
            );
        }
    }

    #[test]
    fn tf_uses_safe_resource_name_dashes_to_underscores() {
        let pack =
            render_min_iam_rules_pack(&input("prod-eu-west-1", "arn:aws:iam::111122223333:role/x"));
        let tf = pack
            .entries
            .iter()
            .find(|e| e.filename == "aws-min-iam.tf")
            .unwrap();
        // Resource names: dashes → underscores.
        assert!(
            tf.content.contains("greentic_prod_eu_west_1"),
            "expected underscored resource name; content:\n{}",
            tf.content
        );
        // But the role name AWS-side keeps dashes for human readability.
        assert!(
            tf.content.contains("greentic-prod-eu-west-1-deployer"),
            "expected dashed role name; content:\n{}",
            tf.content
        );
    }

    #[test]
    fn readme_lists_every_action_and_includes_apply_command() {
        let input = IamRulesPackInput {
            env_id: "prod-eu",
            admin_identity_hint: "arn:aws:iam::111122223333:role/x",
            allowed_actions: &["ecs:CreateService", "ecr:PutImage"],
        };
        let pack = render_min_iam_rules_pack(&input);
        let readme = pack
            .entries
            .iter()
            .find(|e| e.filename == "README.md")
            .unwrap();
        // Every action bulleted.
        for action in input.allowed_actions {
            assert!(
                readme.content.contains(&format!("- `{action}`")),
                "readme must bullet `{action}`; content:\n{}",
                readme.content
            );
        }
        // Apply commands present.
        assert!(readme.content.contains("tofu apply"));
        assert!(readme.content.contains("gtc op credentials rotate prod-eu"));
        // env_id is templated through.
        assert!(readme.content.contains("env `prod-eu`"));
    }

    /// The full verb list produces at least 5 statements: read-only, ECS,
    /// ECR, ALB, and PassRole.
    #[test]
    fn tf_emits_one_statement_per_bucket() {
        let input = IamRulesPackInput {
            env_id: "prod-eu",
            admin_identity_hint: "arn:aws:iam::111122223333:role/x",
            allowed_actions: &[
                "sts:GetCallerIdentity",
                "iam:SimulatePrincipalPolicy",
                "ecs:CreateService",
                "ecs:UpdateService",
                "ecs:CreateTaskSet",
                "ecr:PutImage",
                "elasticloadbalancing:ModifyListener",
                "iam:PassRole",
            ],
        };
        let pack = render_min_iam_rules_pack(&input);
        let tf = &pack
            .entries
            .iter()
            .find(|e| e.filename == "aws-min-iam.tf")
            .unwrap()
            .content;
        // Count statement comment markers.
        let statement_comments: Vec<&str> = tf
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                trimmed.starts_with("# Read-only")
                    || trimmed.starts_with("# ECS rollout")
                    || trimmed.starts_with("# ECR image")
                    || trimmed.starts_with("# ALB listener")
                    || trimmed.starts_with("# iam:PassRole")
            })
            .collect();
        assert!(
            statement_comments.len() >= 5,
            "expected at least 5 statement buckets; got {} in:\n{tf}",
            statement_comments.len()
        );
    }

    /// `iam:PassRole` must be scoped to a placeholder resource (not `*`)
    /// and conditioned on `iam:PassedToService`.
    #[test]
    fn tf_passrole_is_scoped_and_conditioned() {
        let input = IamRulesPackInput {
            env_id: "prod-eu",
            admin_identity_hint: "arn:aws:iam::111122223333:role/x",
            allowed_actions: &[
                "sts:GetCallerIdentity",
                "iam:SimulatePrincipalPolicy",
                "ecs:CreateService",
                "ecr:PutImage",
                "elasticloadbalancing:ModifyListener",
                "iam:PassRole",
            ],
        };
        let pack = render_min_iam_rules_pack(&input);
        let tf = &pack
            .entries
            .iter()
            .find(|e| e.filename == "aws-min-iam.tf")
            .unwrap()
            .content;
        // Find the PassRole statement block (from its comment to the next
        // statement comment or end of statements).
        let passrole_start = tf
            .find("# iam:PassRole")
            .expect("PassRole comment must exist");
        let passrole_block = &tf[passrole_start..];
        assert!(
            passrole_block.contains("iam:PassedToService"),
            "PassRole statement must have iam:PassedToService condition; block:\n{passrole_block}"
        );
        assert!(
            passrole_block.contains("ecs-tasks.amazonaws.com"),
            "PassRole condition must reference ecs-tasks; block:\n{passrole_block}"
        );
        assert!(
            passrole_block.contains("<REPLACE_WITH_ECS_TASK_ROLE_ARN>"),
            "PassRole Resource must be a scoped placeholder, not *; block:\n{passrole_block}"
        );
        // Ensure the PassRole block does NOT use Resource = "*".
        // Find the Resource line within the passrole block.
        for line in passrole_block.lines() {
            if line.contains("Resource") && line.contains('"') {
                assert!(
                    !line.contains("\"*\""),
                    "PassRole Resource must not be \"*\"; line: {line}"
                );
            }
        }
    }

    /// An unrecognized action (not matching any known bucket) must land in
    /// an UNRECOGNIZED review bucket rather than being silently dropped.
    #[test]
    fn tf_unknown_action_falls_to_review_bucket() {
        let input = IamRulesPackInput {
            env_id: "prod-eu",
            admin_identity_hint: "arn:aws:iam::111122223333:role/x",
            allowed_actions: &["sts:GetCallerIdentity", "s3:GetObject"],
        };
        let pack = render_min_iam_rules_pack(&input);
        let tf = &pack
            .entries
            .iter()
            .find(|e| e.filename == "aws-min-iam.tf")
            .unwrap()
            .content;
        assert!(
            tf.contains("UNRECOGNIZED"),
            "unrecognized action must land in UNRECOGNIZED bucket; content:\n{tf}"
        );
        assert!(
            tf.contains("\"s3:GetObject\""),
            "unrecognized action must appear in the HCL; content:\n{tf}"
        );
    }

    #[test]
    fn looks_like_arn_accepts_iam_arns_only() {
        assert!(looks_like_arn("arn:aws:iam::123:role/x"));
        assert!(looks_like_arn("arn:aws-us-gov:iam::123:user/x"));
        // Non-IAM ARN → false; we don't want to silently inline an S3 ARN
        // as a trust principal.
        assert!(!looks_like_arn("arn:aws:s3:::my-bucket"));
        // Non-ARN strings → false.
        assert!(!looks_like_arn("customer-admin"));
        assert!(!looks_like_arn(""));
    }

    /// Actions AWS provides no resource-level scoping for must render at
    /// `Resource = "*"`, never under a `<REPLACE_WITH_*>` placeholder — otherwise
    /// an admin who scopes the placeholder literally gets a role denied those
    /// actions. Renders from the real validated verb list so adding such a verb
    /// without classifying it correctly fails here.
    #[test]
    fn unscopable_verbs_render_at_star() {
        use crate::env_packs::aws::credentials::VALIDATED_IAM_VERBS;
        let star_only = [
            "ecs:RegisterTaskDefinition",
            "ecs:DeregisterTaskDefinition",
            "elasticloadbalancing:DescribeTargetGroups",
        ];
        for verb in VALIDATED_IAM_VERBS {
            let bucket = classify_action(verb);
            assert_ne!(
                bucket,
                ActionBucket::Unrecognized,
                "validated verb `{verb}` must classify to a known bucket"
            );
            let spec = BUCKET_SPECS
                .iter()
                .find(|s| s.bucket == bucket)
                .expect("every bucket has a spec");
            if star_only.contains(verb) {
                assert_eq!(
                    spec.resource, "*",
                    "`{verb}` has no resource-level scoping; it must render at \
                     Resource = \"*\", not `{}`",
                    spec.resource
                );
            }
        }
    }
}
