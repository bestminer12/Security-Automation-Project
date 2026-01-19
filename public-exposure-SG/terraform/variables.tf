variable "aws_region" {
  default = "ap-northeast-2"
}

variable "key_name" {
  description = "EC2 SSH key pair name (optional)"
  type        = string
  default     = null
}
