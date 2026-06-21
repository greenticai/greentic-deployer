terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws    = { source = "hashicorp/aws", version = ">= 5.0" }
    random = { source = "hashicorp/random", version = ">= 3.5" }
  }
}

# offline_plan is AWS-only — google and azurerm providers have no equivalent credential-skip flags.
provider "aws" {
  region                      = var.aws_region
  skip_credentials_validation = var.offline_plan
  skip_requesting_account_id  = var.offline_plan
  skip_metadata_api_check     = var.offline_plan
  access_key                  = var.offline_plan ? "test" : null
  secret_key                  = var.offline_plan ? "test" : null
}
