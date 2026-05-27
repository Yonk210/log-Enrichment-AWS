# ==============================================================
# DynamoDB — IP Metadata Cache
#
# Hash key:  ip_address (String) — the IPv4 address of any ENI
# TTL field: expires_at (Number, Unix epoch seconds) — auto-expires
#            entries that were not refreshed in the last collector cycle.
#            PAY_PER_REQUEST handles the bursty 15-minute upsert pattern
#            without capacity planning.
# ==============================================================

resource "aws_dynamodb_table" "ip_cache" {
  name         = "${var.project_name}-ip-cache"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ip_address"

  attribute {
    name = "ip_address"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-ip-cache"
  })
}
