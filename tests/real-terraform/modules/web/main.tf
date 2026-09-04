variable "logging_enabled" {
  type    = bool
  default = true
}

resource "aws_s3_bucket" "site" {
  bucket_prefix = "tf-nag-real-"
}

resource "aws_s3_bucket_logging" "site" {
  count = var.logging_enabled ? 1 : 0

  bucket        = aws_s3_bucket.site.id
  target_bucket = aws_s3_bucket.site.id
  target_prefix = "logs/"
}
