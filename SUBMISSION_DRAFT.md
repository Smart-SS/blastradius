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

**Complete after an actual AWS console connection:** name the coding agent, describe how it was connected to the console, add redacted proof, and explain its concrete contribution to the build or deployment. Do not claim a connection until it has happened.

## Demo and evidence

- **Live AWS URL:** https://dcy31xag10fko.cloudfront.net
- **Agent-to-console proof:** [ADD REDACTED SCREENSHOT OR TRANSCRIPT]
- **AWS services:** S3 and CloudFront with Origin Access Control.
- **Demo:** Click "Try a risky plan" to show the database replacement, `deletion_protection` removal, `skip_final_snapshot`, and new public exposure — each with its trigger, impact, and verify/rollback checklist. Then click "Try a safe plan" to show the contrast: a clean, standard-review verdict. Finish with the review questions and resource list.
- **Validation:** Confirm the public URL opens without login, the sample analysis works, and the judging bot can retrieve the page and assets.

## Next step

Improve resource-level context and review annotations, then validate the findings against real change review workflows with consenting teams. Do not enter user counts, cost savings, or error reductions without measurement.
