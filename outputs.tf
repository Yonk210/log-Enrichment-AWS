# ==============================================================
# Outputs — Key resource identifiers for downstream use
# ==============================================================

output "dynamodb_table_name" {
  description = "Name of the DynamoDB IP metadata cache table."
  value       = aws_dynamodb_table.ip_cache.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB IP metadata cache table."
  value       = aws_dynamodb_table.ip_cache.arn
}

output "firehose_stream_name" {
  description = "Name of the Firehose delivery stream receiving VPC Flow Logs."
  value       = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.name
}

output "firehose_stream_arn" {
  description = "ARN of the Firehose delivery stream."
  value       = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.arn
}

output "s3_backup_bucket_name" {
  description = "Name of the S3 bucket used as primary or error-backup destination."
  value       = aws_s3_bucket.firehose_backup.id
}

output "collector_lambda_arn" {
  description = "ARN of the Cache Worker (collector) Lambda."
  value       = aws_lambda_function.collector.arn
}

output "enricher_lambda_arn" {
  description = "ARN of the Firehose Processor (enricher) Lambda."
  value       = aws_lambda_function.enricher.arn
}

output "target_vpc_ids" {
  description = "List of VPC IDs that have direct-to-Firehose Flow Logs enabled."
  value       = local.target_vpc_ids
}
