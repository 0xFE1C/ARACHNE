resource "aws_security_group" "open" {
  name = "open-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    # A security group open to the world.
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "arachne-lab-public"
  acl    = "public-read"
}

resource "aws_iam_policy" "wildcard" {
  name = "wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_db_instance" "public" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
}