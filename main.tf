# ==============================================================
# terraform-aws-log-enricher — Core Infrastructure
# ==============================================================

# ------------------------------------------------------------
# VPC Discovery
# If vpc_ids is empty, discover all VPCs in the account.
# ------------------------------------------------------------

data "aws_vpcs" "all" {}

locals {
  target_vpc_ids = length(var.vpc_ids) > 0 ? var.vpc_ids : data.aws_vpcs.all.ids
}

# ------------------------------------------------------------
# Cross-variable validation
# Terraform validation blocks cannot reference other variables,
# so we use locals with tobool() to produce plan-time errors.
# ------------------------------------------------------------

locals {
  _validate_datadog = (
    var.siem_destination_type == "datadog" && var.datadog_api_key == ""
    ? tobool("ERROR: datadog_api_key is required when siem_destination_type is 'datadog'")
    : true
  )
  _validate_splunk_endpoint = (
    var.siem_destination_type == "splunk" && var.splunk_hec_endpoint == ""
    ? tobool("ERROR: splunk_hec_endpoint is required when siem_destination_type is 'splunk'")
    : true
  )
  _validate_splunk_token = (
    var.siem_destination_type == "splunk" && var.splunk_hec_token == ""
    ? tobool("ERROR: splunk_hec_token is required when siem_destination_type is 'splunk'")
    : true
  )
}

# ------------------------------------------------------------
# S3 Bucket
# Always provisioned regardless of SIEM destination type.
# - When siem_destination_type = "s3": primary log destination.
# - When siem_destination_type = "datadog" or "splunk": Firehose
#   requires an S3 bucket to store failed-delivery records.
# ------------------------------------------------------------

resource "aws_s3_bucket" "firehose_backup" {
  bucket = "${var.project_name}-firehose-${data.aws_caller_identity.current.account_id}"

  tags = merge(var.tags, {
    Name = "${var.project_name}-firehose-backup"
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "firehose_backup" {
  bucket = aws_s3_bucket.firehose_backup.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "firehose_backup" {
  bucket = aws_s3_bucket.firehose_backup.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "firehose_backup" {
  bucket = aws_s3_bucket.firehose_backup.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------
# Amazon Data Firehose Delivery Stream
#
# Uses dynamic blocks to switch between three destination types
# controlled by var.siem_destination_type. Only one dynamic block
# evaluates to a non-empty list at any given apply.
#
# The enricher Lambda is wired as a transformation processor on
# all three destination types.
# ------------------------------------------------------------

resource "aws_kinesis_firehose_delivery_stream" "vpc_flow_logs" {
  name = "${var.project_name}-vpc-flow-logs"

  destination = (
    var.siem_destination_type == "s3"      ? "extended_s3" :
    var.siem_destination_type == "datadog" ? "http_endpoint" :
    "splunk"
  )

  # ---- Destination: S3 ----
  dynamic "extended_s3_configuration" {
    for_each = var.siem_destination_type == "s3" ? [1] : []

    content {
      role_arn   = aws_iam_role.firehose.arn
      bucket_arn = aws_s3_bucket.firehose_backup.arn

      buffering_size     = var.firehose_buffer_size_mb
      buffering_interval = var.firehose_buffer_interval_sec

      # Hive-compatible prefix for easy Athena/Glue integration
      prefix              = "vpc-flow-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      error_output_prefix = "errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"

      processing_configuration {
        enabled = true

        processors {
          type = "Lambda"

          parameters {
            parameter_name  = "LambdaArn"
            parameter_value = "${aws_lambda_function.enricher.arn}:$LATEST"
          }
        }
      }
    }
  }

  # ---- Destination: Datadog ----
  dynamic "http_endpoint_configuration" {
    for_each = var.siem_destination_type == "datadog" ? [1] : []

    content {
      # US1 Datadog Firehose intake endpoint.
      # For other Datadog regions, override this variable in your root module.
      url        = "https://aws-kinesis-http-intake.logs.datadoghq.com/v1/input"
      name       = "Datadog"
      access_key = var.datadog_api_key

      buffering_size     = var.firehose_buffer_size_mb
      buffering_interval = var.firehose_buffer_interval_sec
      role_arn           = aws_iam_role.firehose.arn

      s3_backup_mode = "FailedDataOnly"

      s3_configuration {
        role_arn           = aws_iam_role.firehose.arn
        bucket_arn         = aws_s3_bucket.firehose_backup.arn
        buffering_size     = 5
        buffering_interval = 300
        compression_format = "GZIP"
      }

      processing_configuration {
        enabled = true

        processors {
          type = "Lambda"

          parameters {
            parameter_name  = "LambdaArn"
            parameter_value = "${aws_lambda_function.enricher.arn}:$LATEST"
          }
        }
      }
    }
  }

  # ---- Destination: Splunk ----
  dynamic "splunk_configuration" {
    for_each = var.siem_destination_type == "splunk" ? [1] : []

    content {
      hec_endpoint               = var.splunk_hec_endpoint
      hec_token                  = var.splunk_hec_token
      hec_endpoint_type          = "Event"
      hec_acknowledgment_timeout = 600

      buffering_size     = var.firehose_buffer_size_mb
      buffering_interval = var.firehose_buffer_interval_sec

      s3_backup_mode = "FailedEventsOnly"

      s3_configuration {
        role_arn           = aws_iam_role.firehose.arn
        bucket_arn         = aws_s3_bucket.firehose_backup.arn
        buffering_size     = 5
        buffering_interval = 300
        compression_format = "GZIP"
      }

      processing_configuration {
        enabled = true

        processors {
          type = "Lambda"

          parameters {
            parameter_name  = "LambdaArn"
            parameter_value = "${aws_lambda_function.enricher.arn}:$LATEST"
          }
        }
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-vpc-flow-logs"
  })

  depends_on = [aws_iam_role_policy.firehose]
}

# ------------------------------------------------------------
# VPC Flow Logs — Direct-to-Firehose
#
# One aws_flow_log resource per target VPC. The custom log format
# includes modern fields (reject-reason, tcp-flags, traffic-path,
# pkt-src-aws-service) required by the enricher's troubleshooting rules.
#
# Note: $$ in HCL strings escapes to a literal $ in the AWS API call.
# ------------------------------------------------------------

resource "aws_flow_log" "vpc" {
  for_each = toset(local.target_vpc_ids)

  vpc_id               = each.value
  traffic_type         = "ALL"
  iam_role_arn         = aws_iam_role.flow_logs_delivery.arn
  log_destination      = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.arn
  log_destination_type = "kinesis-data-firehose"

  log_format = "$${version} $${account-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${reject-reason} $${tcp-flags} $${traffic-path} $${pkt-src-aws-service}"

  tags = merge(var.tags, {
    Name = "${var.project_name}-flow-log-${each.value}"
  })
}

# ------------------------------------------------------------
# EventBridge — Collector Schedule
# ------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "collector_schedule" {
  name                = "${var.project_name}-collector-schedule"
  description         = "Triggers the Cache Worker Lambda to refresh IP metadata."
  schedule_expression = var.collector_schedule
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "collector" {
  rule      = aws_cloudwatch_event_rule.collector_schedule.name
  target_id = "CollectorLambda"
  arn       = aws_lambda_function.collector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_collector" {
  statement_id  = "AllowEventBridgeInvokeCollector"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.collector_schedule.arn
}
