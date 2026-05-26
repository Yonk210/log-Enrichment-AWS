# Example: Splunk HEC destination
# Run: terraform init && terraform plan -var="splunk_hec_endpoint=..." -var="splunk_hec_token=..."

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "splunk_hec_endpoint" {
  description = "Splunk HEC endpoint URL."
  type        = string
}

variable "splunk_hec_token" {
  description = "Splunk HEC token."
  type        = string
  sensitive   = true
}

module "log_enricher" {
  source = "../../"

  project_name          = "log-enricher-prod"
  siem_destination_type = "splunk"
  splunk_hec_endpoint   = var.splunk_hec_endpoint
  splunk_hec_token      = var.splunk_hec_token

  tags = {
    Environment = "prod"
    ManagedBy   = "terraform"
  }
}
