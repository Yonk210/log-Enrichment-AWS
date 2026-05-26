# Example: S3 destination (default — zero external credentials required)
# Run: terraform init && terraform plan

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "log_enricher" {
  source = "../../"

  project_name          = "log-enricher-lab"
  siem_destination_type = "s3"

  tags = {
    Environment = "lab"
    ManagedBy   = "terraform"
  }
}

output "s3_bucket" {
  value = module.log_enricher.s3_backup_bucket_name
}

output "firehose_stream" {
  value = module.log_enricher.firehose_stream_name
}
