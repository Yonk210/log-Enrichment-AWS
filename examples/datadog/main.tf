# Example: Datadog HTTP intake destination
# Run: terraform init && terraform plan -var="datadog_api_key=YOUR_KEY"

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "datadog_api_key" {
  description = "Datadog API key for Firehose HTTP intake."
  type        = string
  sensitive   = true
}

module "log_enricher" {
  source = "../../"

  project_name          = "log-enricher-prod"
  siem_destination_type = "datadog"
  datadog_api_key       = var.datadog_api_key

  tags = {
    Environment = "prod"
    ManagedBy   = "terraform"
  }
}
