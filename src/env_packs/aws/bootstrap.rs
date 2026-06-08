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

fn render_terraform(input: &IamRulesPackInput<'_>) -> String {
    // The HCL Action list is rendered as a JSON-style list inside the
    // inline policy document. Order mirrors `allowed_actions` for
    // reviewer-friendly diffs.
    let actions_json = input
        .allowed_actions
        .iter()
        .map(|a| format!("            \"{a}\""))
        .collect::<Vec<_>>()
        .join(",\n");

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
      {{
        Effect = "Allow"
        Action = [
{actions_json}
        ]
        Resource = "*"
      }}
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
        actions_json = actions_json,
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

## How to apply

1. Review `aws-min-iam.tf`. The trust principal is currently:

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

   All seven capabilities (`{sts_cap}` + the six IAM verbs above) must
   pass before `gtc op deploy {env_id}` is honored.

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
}
