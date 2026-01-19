
resource "aws_security_group" "public_ssh_sg" {
  name        = "public-ssh-sg"
  description = "Public SSH open (intentional misconfig)"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "public_ec2" {
  ami                    = "ami-0c9c942bd7bf113a2" # Amazon Linux 2023 (서울)
  instance_type          = "t2.micro"
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.public_ssh_sg.id]

  associate_public_ip_address = true

  tags = {
    Name = "public-exposure-ec2"
    Risk = "High"
  }
}
