# ==============================================================
# Shared data source — used across all policies for account-scoped ARNs
# ==============================================================

data "aws_caller_identity" "current" {}

# ==============================================================
# Role 1: CollectorRole
# Assumed by the Cache Worker Lambda every 15 minutes.
# Reads EC2 topology metadata and writes enriched records to DynamoDB.
# ==============================================================

resource "aws_iam_role" "collector" {
  name = "${var.project_name}-collector-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "collector" {
  name = "${var.project_name}-collector-policy"
  role = aws_iam_role.collector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2ReadMetadata"
        Effect = "Allow"
        Action = [
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeInstances",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkAcls"
        ]
        Resource = "*"
      },
      {
        Sid      = "DynamoDBWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.ip_cache.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-collector:*"
      }
    ]
  })
}

# ==============================================================
# Role 2: EnricherRole
# Assumed by the Firehose Transformation Lambda on each invocation.
# Needs read-only DynamoDB access for BatchGetItem lookups.
# ==============================================================

resource "aws_iam_role" "enricher" {
  name = "${var.project_name}-enricher-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "enricher" {
  name = "${var.project_name}-enricher-policy"
  role = aws_iam_role.enricher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoDBRead"
        Effect   = "Allow"
        Action   = ["dynamodb:BatchGetItem"]
        Resource = aws_dynamodb_table.ip_cache.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-enricher:*"
      }
    ]
  })
}

# ==============================================================
# Role 3: FlowLogsDeliveryRole
# Trusted by the VPC Flow Logs service (delivery.logs.amazonaws.com)
# to write records directly into the Firehose stream.
#
# CRITICAL: Without this role, aws_flow_log resources will be created
# successfully by Terraform but logs will silently fail to deliver.
# ==============================================================

resource "aws_iam_role" "flow_logs_delivery" {
  name = "${var.project_name}-flow-logs-delivery-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "delivery.logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "flow_logs_delivery" {
  name = "${var.project_name}-flow-logs-delivery-policy"
  role = aws_iam_role.flow_logs_delivery.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "FirehoseWrite"
      Effect   = "Allow"
      Action   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
      Resource = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.arn
    }]
  })
}

# ==============================================================
# Role 4: FirehoseRole
# Assumed by the Firehose delivery stream itself.
# Needs S3 write access (primary or backup) and permission to invoke
# the enricher Lambda as a transformation processor.
# ==============================================================

resource "aws_iam_role" "firehose" {
  name = "${var.project_name}-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "firehose" {
  name = "${var.project_name}-firehose-policy"
  role = aws_iam_role.firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Write"
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.firehose_backup.arn,
          "${aws_s3_bucket.firehose_backup.arn}/*"
        ]
      },
      {
        Sid      = "LambdaInvoke"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.enricher.arn
      }
    ]
  })
}
