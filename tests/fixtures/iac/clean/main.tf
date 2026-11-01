# The clean Terraform fixture: no rule the IaC review knows fires here.
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "orders" {
  publicly_accessible = false
  encrypted           = true
}

resource "aws_s3_bucket" "exports" {
  acl = "private"
}
