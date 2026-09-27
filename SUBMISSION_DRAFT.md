# AWS Zero to Shipped submission draft

**Project:** BlastRadius

**Category:** Workplace efficiency `#workplace-efficiency`

**Lane:** Startup `#startups`

## One-line pitch

BlastRadius turns a Terraform plan into a clear change brief so cloud teams can spot risky infrastructure changes before an apply.

## The problem

Terraform plans can be long and difficult to scan under time pressure. A destructive resource replacement, a storage deletion, or a change that makes a service publicly reachable can be missed during review. Small teams need a fast first pass that helps reviewers ask the right questions.

## What the app does

Export a Terraform plan as JSON, open BlastRadius, and load the file. It runs locally in the browser. Instead of a flat list of warnings, it answers one memorable question: **"What could break if I apply this plan?"** For each risky resource it shows the exact change that triggered the finding (for example `deletion_protection` true → false, or ingress opened to `0.0.0.0/0`), the likely service impact, and a concrete verify-before-apply and rollback checklist. Two sample plans ship with the app: a routine safe deploy and a dangerous change that combines a database replacement with newly public access — so the before-and-after story is clear in minutes without touching real infrastructure.

## Architecture

CloudFront serves the static app over HTTPS from a private S3 origin protected by Origin Access Control. Browser JavaScript analyzes the plan locally. No plan file is uploaded or persisted by the application.

## Why it matters

The goal is a more consistent review, especially when the person approving a change did not write the Terraform. The interface turns technical diffs into an actionable conversation. The current prototype is a deterministic review aid and does not claim to replace expert review or policy enforcement.

## Build process and coding agent

Built from hands-on experience reviewing Terraform changes across many AWS accounts. A coding agent — **GitHub Copilot in VS Code** — made the following documented, verifiable contributions:

- Implemented the browser interface and the deterministic risk-rule engine (triggers, impacts, verify/rollback checklists) in `app.js`.
- Deployed the infrastructure with the AWS CLI using my credentials: created/updated the CloudFormation stack `blast-radius-contest` (private S3 bucket + CloudFront distribution with Origin Access Control), uploaded assets with correct content types, and invalidated the CloudFront cache.
- Connected to my AWS account through the **AWS MCP server** and performed a read-only inspection of the live distribution (`cloudfront:ListDistributions`, `cloudfront:GetDistribution`), confirming status **Deployed**, viewer protocol `redirect-to-https`, the private S3 origin `blast-radius-contest-assetsbucket-*`, and the attached Origin Access Control.
- Diagnosed and fixed real defects along the way: a merged/duplicated `app.js`, a broken content-type `case` in `deploy.sh`, and over-certain risk wording.

**Proof:** [ADD REDACTED TRANSCRIPT — paste the AWS MCP tool call and result showing the CloudFront inspection, plus the deploy output; redact the AWS account ID before publishing.]

## Demo and evidence

- **Live AWS URL:** https://dcy31xag10fko.cloudfront.net
- **Source code:** https://github.com/Smart-SS/blastradius
- **Agent-to-console proof:** [ADD REDACTED SCREENSHOT OR TRANSCRIPT]
- **AWS services:** S3 and CloudFront with Origin Access Control, provisioned via CloudFormation.
- **Demo:** Click "Try a risky plan" to show the database replacement, `deletion_protection` removal, `skip_final_snapshot`, and new public exposure — each with its trigger, impact, and verify/rollback checklist. Then click "Try a safe plan" to show the contrast: a clean, standard-review verdict. Finish with the review questions and resource list.
- **Validation:** Confirm the public URL opens without login, the sample analysis works, and the judging bot can retrieve the page and assets.

## Next step

Improve resource-level context and review annotations, then validate the findings against real change review workflows with consenting teams. Do not enter user counts, cost savings, or error reductions without measurement.
