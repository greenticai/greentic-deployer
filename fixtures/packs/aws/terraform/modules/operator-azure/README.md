# Operator Azure Module Skeleton

This directory is the Azure parity scaffold for the terraform deployment pack.

Current intent:

- preserve the same canonical inputs as the AWS operator module
- converge on the same canonical outputs:
  - `operator_endpoint`
  - `admin_ca_secret_ref`
  - `admin_server_cert_secret_ref`
  - `admin_server_key_secret_ref`

Current status:

- output contract and naming are implemented
- admin CA, server cert, and server key can be materialized into an existing
  Azure Key Vault when `azure_key_vault_id` is provided
- a minimal Azure Container Apps runtime is provisioned with the same
  bundle/admin env contract used by AWS
- `operator_endpoint` already resolves from `public_base_url` when provided
- this module exists so Azure parity work can land without changing the pack layout again

Current limitations:

- ingress and networking are still simpler than the AWS ALB path
- logs and status integration are not yet at AWS depth
