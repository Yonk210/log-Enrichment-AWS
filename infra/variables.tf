# ==============================================================
# terraform-aws-log-enricher — Input Variables
# ==============================================================

variable "aws_region" {
  description = "AWS region where all resources are deployed."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix applied to every resource name for namespacing. Use lowercase letters, numbers, and hyphens only."
  type        = string
  default     = "log-enricher"
}

variable "vpc_ids" {
  description = "List of VPC IDs to enable Flow Logs on. Leave empty to target all VPCs in the account automatically."
  type        = list(string)
  default     = []
}

variable "siem_destination_type" {
  description = "Primary SIEM output destination for the Firehose stream. One of: s3, datadog, splunk."
  type        = string
  default     = "s3"

  validation {
    condition     = contains(["s3", "datadog", "splunk"], var.siem_destination_type)
    error_message = "siem_destination_type must be one of: s3, datadog, splunk."
  }
}

variable "datadog_api_key" {
  description = "Datadog API key. Required when siem_destination_type is 'datadog'."
  type        = string
  default     = ""
  sensitive   = true
}

variable "splunk_hec_endpoint" {
  description = "Splunk HEC endpoint URL (e.g. https://http-inputs-myorg.splunkcloud.com). Required when siem_destination_type is 'splunk'."
  type        = string
  default     = ""
}

variable "splunk_hec_token" {
  description = "Splunk HEC token. Required when siem_destination_type is 'splunk'."
  type        = string
  default     = ""
  sensitive   = true
}

variable "collector_schedule" {
  description = "EventBridge schedule expression that triggers the Cache Worker Lambda."
  type        = string
  default     = "rate(15 minutes)"
}

variable "dynamodb_ttl_minutes" {
  description = "Minutes before a DynamoDB cache entry expires. Should be greater than the collector_schedule interval."
  type        = number
  default     = 30
}

variable "firehose_buffer_size_mb" {
  description = "Firehose buffer size in MB before flushing to the destination (1–128)."
  type        = number
  default     = 1
}

variable "firehose_buffer_interval_sec" {
  description = "Firehose buffer interval in seconds before flushing to the destination (60–900)."
  type        = number
  default     = 60
}

variable "log_retention_days" {
  description = "Retention period in days for Lambda CloudWatch Log Groups."
  type        = number
  default     = 14
}

variable "tags" {
  description = "Map of tags to apply to all provisioned AWS resources."
  type        = map(string)
  default     = {}
}
