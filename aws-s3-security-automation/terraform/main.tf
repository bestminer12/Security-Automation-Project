provider "aws" {
  region = "ap-northeast-2"
}
 
############################
# S3 Bucket
############################
resource "aws_s3_bucket" "lab_bucket" {
  bucket = "seokhyun-s3-exposure-lab-001"  # ← 고유 이름으로 변경

  tags = {
    Project     = "S3ExposureLab"
    Environment = "lab"
    Owner       = "seokhyun"
  }
}

############################
# Public Access Block OFF
############################
resource "aws_s3_bucket_public_access_block" "lab_bucket_pab" {
  bucket = aws_s3_bucket.lab_bucket.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}
