# ==============================================================
# Lambda Packaging
#
# archive_file zips the function source directory at plan time.
# Output path is in .builds/ (gitignored). source_code_hash
# triggers redeployment whenever the source changes.
# ==============================================================

data "archive_file" "collector" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/collector"
  output_path = "${path.module}/../.builds/collector.zip"
}

data "archive_file" "enricher" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/enricher"
  output_path = "${path.module}/../.builds/enricher.zip"
}

# ==============================================================
# CloudWatch Log Groups
#
# Created explicitly (rather than letting Lambda auto-create them)
# so that the log_retention_days variable is honoured from day one.
# ==============================================================

resource "aws_cloudwatch_log_group" "collector" {
  name              = "/aws/lambda/${var.project_name}-collector"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "enricher" {
  name              = "/aws/lambda/${var.project_name}-enricher"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# ==============================================================
# Collector Lambda — Cache Worker (Cold Path)
# Triggered by EventBridge every 15 minutes.
# 5-minute timeout to handle large accounts with many ENIs.
# ==============================================================

resource "aws_lambda_function" "collector" {
  function_name    = "${var.project_name}-collector"
  role             = aws_iam_role.collector.arn
  handler          = "collector.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.collector.output_path
  source_code_hash = data.archive_file.collector.output_base64sha256
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      DYNAMODB_TABLE_NAME  = aws_dynamodb_table.ip_cache.name
      DYNAMODB_TTL_MINUTES = tostring(var.dynamodb_ttl_minutes)
      AWS_REGION_NAME      = var.aws_region
    }
  }

  # Ensure the log group exists before Lambda is created, so the first
  # invocation does not trigger a race condition on log group creation.
  depends_on = [
    aws_cloudwatch_log_group.collector,
    aws_iam_role_policy.collector
  ]

  tags = var.tags
}

# ==============================================================
# Enricher Lambda — Firehose Transformation Processor (Hot Path)
# Invoked inline by Firehose for every buffered batch.
# 3-minute timeout (Firehose transformation max is 5 min).
# ==============================================================

resource "aws_lambda_function" "enricher" {
  function_name    = "${var.project_name}-enricher"
  role             = aws_iam_role.enricher.arn
  handler          = "enricher.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.enricher.output_path
  source_code_hash = data.archive_file.enricher.output_base64sha256
  timeout          = 180
  memory_size      = 512

  environment {
    variables = {
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.ip_cache.name
      AWS_REGION_NAME     = var.aws_region
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.enricher,
    aws_iam_role_policy.enricher
  ]

  tags = var.tags
}

# Allow Firehose to invoke the enricher Lambda
resource "aws_lambda_permission" "allow_firehose_enricher" {
  statement_id  = "AllowFirehoseInvokeEnricher"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enricher.function_name
  principal     = "firehose.amazonaws.com"
  source_arn    = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.arn
}
