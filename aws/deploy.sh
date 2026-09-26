#!/usr/bin/env bash
set -euo pipefail

stack_name="${1:-blast-radius-contest}"
aws_region="${AWS_REGION:-us-east-1}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(dirname "$script_dir")"

aws sts get-caller-identity >/dev/null
aws cloudformation deploy --region "$aws_region" --stack-name "$stack_name" --template-file "$script_dir/cloudformation.yaml" --no-fail-on-empty-changeset
bucket_name="$(aws cloudformation describe-stacks --region "$aws_region" --stack-name "$stack_name" --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue | [0]" --output text)"
distribution_id="$(aws cloudformation describe-stacks --region "$aws_region" --stack-name "$stack_name" --query "Stacks[0].Outputs[?OutputKey=='DistributionId'].OutputValue | [0]" --output text)"
public_url="$(aws cloudformation describe-stacks --region "$aws_region" --stack-name "$stack_name" --query "Stacks[0].Outputs[?OutputKey=='PublicURL'].OutputValue | [0]" --output text)"
for asset in index.html app.js styles.css; do
  case "$asset" in
    *.html) content_type="text/html";;
    *.js) content_type="application/javascript";;
    *.css) content_type="text/css";;
    *) content_type="application/octet-stream";;
  esac
  aws s3 cp "$app_dir/$asset" "s3://$bucket_name/$asset" --region "$aws_region" --content-type "$content_type" --cache-control 'public,max-age=300'
done
aws cloudfront create-invalidation --distribution-id "$distribution_id" --paths '/*' >/dev/null
printf 'Public URL: %s\nDistribution ID: %s\n' "$public_url" "$distribution_id"
