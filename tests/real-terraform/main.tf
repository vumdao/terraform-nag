terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "eu-west-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

module "web" {
  source = "./modules/web"
}

module "web_many" {
  for_each = {
    blue  = true
    green = false
  }
  source         = "./modules/web"
  logging_enabled = each.value
}

resource "aws_sqs_queue" "insecure" {
  name = "tf-nag-real-insecure"
}

resource "aws_sqs_queue" "insecure_count" {
  count = 2
  name  = "tf-nag-real-insecure-count-${count.index}"
}

resource "aws_sqs_queue" "insecure_for_each" {
  for_each = {
    blue  = "blue"
    green = "green"
  }
  name = "tf-nag-real-insecure-${each.key}"
}

resource "aws_dynamodb_table" "secure" {
  name         = "tf-nag-real-secure"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_kms_key" "secure" {
  description         = "tf-nag real-plan fixture"
  enable_key_rotation = true
}
