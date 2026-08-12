# Phase 5 test fixture - DELIBERATELY INSECURE. Not deployed anywhere.
# The credential values below are fake/non-functional placeholders.
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAFAKEFIXTURE00001"
  secret_key = "wJalrFAKEfixtureEXAMPLEKEY000000000000000"
}

resource "aws_s3_bucket" "public_data" {
  bucket = "prod-public-data"
  acl    = "public-read"
}

resource "aws_security_group" "wide_open" {
  name = "wide-open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin_everything" {
  name = "admin-everything"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
