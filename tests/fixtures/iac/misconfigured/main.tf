# The misconfigured Terraform fixture: every rule it trips is one the shipped IaC
# review (m5.tfstate-exposure, ch05#12) and the admission/IaC policy engine know.
resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "orders" {
  publicly_accessible = true
  encrypted           = false
}

resource "aws_s3_bucket" "exports" {
  acl = "public-read"
}

resource "aws_iam_role_policy" "app" {
  policy = "{\"Action\": \"*\", \"Resource\": \"*\"}"
}
