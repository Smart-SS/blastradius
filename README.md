# BlastRadius

An original, browser-based Terraform change review app for the AWS Zero to Shipped 2026 challenge. It turns a `terraform show -json` plan into a risk brief built on one promise: *show the evidence behind a risky change, and show what remains unknown.* For each risky resource it shows the exact triggering change, the likely impact, and resource-specific verify/rollback checks; a dependency map derived only from actual plan references (with unknowns labeled honestly); a risky-vs-revised comparison reported as fewer detected risks; and an exportable Markdown review brief for pull requests. Plans are read only in the browser; the app makes no network requests for plan content.

## Run locally

From this directory, run `python3 -m http.server 8080` and open `http://localhost:8080`. Click **Try a risky plan** (an agent-proposed change with a database replacement and new public exposure), then **Compare the revised plan** to see which findings resolve and which remain, or **Try a safe plan** for the clean-verdict contrast.

## Review your own plan

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

Open the app and select `plan.json`. **Terraform plan JSON can contain sensitive values.** Only use plans you are authorized to handle. The app does not upload the file, but do not publish real plan files or screenshots with private details.

## Hosting on AWS

The `aws/cloudformation.yaml` stack provisions a private S3 bucket and a public HTTPS CloudFront distribution with Origin Access Control. With AWS CLI credentials for the entrant's account, run `bash aws/deploy.sh` from this directory. The script prints the public URL. AWS may charge for S3, CloudFront, and requests; review usage and budget in your account. This deployment must be completed in the entrant's own AWS account. Do not use a non-AWS URL for the contest submission.

## Contest evidence to collect

- Screenshot or redacted transcript of the coding agent connected to the AWS console during the submission period.
- Public CloudFront URL that loads the app and successfully runs the sample plan.
- AWS services used, architecture and development process.
- Category `#workplace-efficiency`, lane `#startups`.

## Limitations

Heuristics are deliberately conservative and do not inspect every Terraform provider or implicit dependency. No AI risk claims are made. A human still reviews the full plan and rollout controls.
