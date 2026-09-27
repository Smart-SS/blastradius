# AWS Zero to Shipped submission draft

**Project:** BlastRadius

**Category:** Workplace efficiency `#workplace-efficiency`

**Lane:** Startup `#startups`

## One-line pitch

BlastRadius turns a Terraform plan into a clear change brief so cloud teams can spot risky infrastructure changes before an apply.

## The problem

Terraform plans can be long and difficult to scan under time pressure. A destructive resource replacement, a storage deletion, or a change that makes a service publicly reachable can be missed during review. Small teams need a fast first pass that helps reviewers ask the right questions.

## What the app does

Export a Terraform plan as JSON, open BlastRadius, and load the file. It runs locally in the browser, built on one promise: **show the evidence behind a risky change, and show what remains unknown.** For each risky resource it shows the exact change that triggered the finding (for example `deletion_protection` true → false, or ingress opened to `0.0.0.0/0`), the likely impact, and **resource-specific** recovery checks — database findings talk about snapshots and PITR, S3 findings about versioning, replication, and object inventory. A dependency map is derived only from actual configuration references in the plan; resources whose relationships cannot be established are labeled unknown rather than guessed. A **risky-vs-revised comparison** shows precisely which findings resolve and which remain — reported as *fewer detected risks*, never as a guarantee of safety. An **Export review brief** button produces a Markdown report with evidence, unresolved questions, and approval checkboxes that an engineer can attach to a pull request.

The demo follows one scenario: an AI coding agent proposes an infrastructure change; BlastRadius exposes a destructive database replacement and public ingress with evidence; the engineer's revised plan is compared side by side, showing six findings resolved and three remaining.

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
- **Demo:** Click "Try a risky plan" to show the database replacement, `deletion_protection` removal, `skip_final_snapshot`, and new public exposure — each with evidence, impact, and resource-specific verify/rollback checks, plus the dependency map with unknowns labeled. Then click "Compare the revised plan" to show which findings resolve and which remain. Finish by exporting the Markdown review brief.
- **Validation:** Confirm the public URL opens without login, the sample analysis works, and the judging bot can retrieve the page and assets.

## Next step

Run a small, honestly reported evaluation: have three engineers review an unfamiliar plan with and without BlastRadius, recording what they catch, what confuses them, and how long the review takes. Then integrate the exported review brief into pull-request workflows (a CI step that comments the brief on the PR). Do not enter user counts, cost savings, or error reductions without measurement.
