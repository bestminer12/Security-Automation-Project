     
resource "aws_security_group" "public_ssh_sg" {
  name        = "public-ssh-sg4"
  description = "Public SSH open (intentional misconfig) "

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

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}


resource "aws_instance" "public_ec2" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.public_ssh_sg.id]

  associate_public_ip_address = true

  tags = {
    Name = "public-exposure-ec2"
    Risk = "High"
  }
}
