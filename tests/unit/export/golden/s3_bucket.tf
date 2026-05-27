# Golden fragment: single S3 bucket.
# Tests normalize whitespace, so exact indentation / newlines are not material.
# Every non-comment line here must appear (normalized) in the generated .tf.
resource "aws_s3_bucket"
bucket = "my-bucket"
