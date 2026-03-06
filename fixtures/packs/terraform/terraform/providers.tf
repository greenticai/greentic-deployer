terraform {
  required_version = ">= 1.8.0"
  backend "s3" {}
}

provider "kubernetes" {}
provider "aws" {}

