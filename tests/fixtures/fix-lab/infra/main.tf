# The payment API's data tier (lab repository: the tests plant its misconfigurations).

terraform {
  required_version = ">= 1.5"
}

resource "aws_db_instance" "payments" {
  identifier          = "payments"
  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  storage_encrypted   = true
  skip_final_snapshot = false
}

resource "aws_s3_bucket" "reports" {
  bucket = "payments-reports"
  acl    = "private"
  tags = {
    Environment = "production"
  }
}
