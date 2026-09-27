"use strict";
// All plan processing stays in the browser. Never render raw plan values or sensitive fields.
const $ = id => document.getElementById(id);

// --- Demo plans -------------------------------------------------------------
// Three plans tell one story: a risky agent-proposed change, the engineer's
// revised version, and a routine safe deploy. Each includes a configuration
// block so the dependency reference list can be derived from real references.
const samples = {
  safe: {
    label: "Sample: routine web tier deploy",
    plan: {
      format_version: "1.2",
      resource_changes: [
        {address:"aws_ecs_service.web",type:"aws_ecs_service",change:{actions:["update"],before:{desired_count:3},after:{desired_count:4}}},
        {address:"aws_appautoscaling_target.web",type:"aws_appautoscaling_target",change:{actions:["update"],before:{max_capacity:6},after:{max_capacity:8}}},
        {address:"aws_cloudwatch_metric_alarm.cpu_high",type:"aws_cloudwatch_metric_alarm",change:{actions:["create"],before:null,after:{alarm_name:"web-cpu-high"}}},
        {address:"aws_s3_bucket_lifecycle_configuration.logs",type:"aws_s3_bucket_lifecycle_configuration",change:{actions:["create"],before:null,after:{rule:[{id:"expire-90d"}]}}}
      ],
      configuration:{root_module:{resources:[
        {address:"aws_appautoscaling_target.web",expressions:{resource_id:{references:["aws_ecs_service.web"]}}},
        {address:"aws_cloudwatch_metric_alarm.cpu_high",expressions:{dimensions:{references:["aws_ecs_service.web"]}}}
      ]}}
    }
  },
  risky: {
    label: "Sample: agent-proposed order service change (risky)",
    plan: {
      format_version: "1.2",
      resource_changes: [
        {address:"aws_db_instance.orders",type:"aws_db_instance",change:{actions:["delete","create"],before:{deletion_protection:true,skip_final_snapshot:false,instance_class:"db.r6g.large"},after:{deletion_protection:false,skip_final_snapshot:true,instance_class:"db.r6g.xlarge"}}},
        {address:"aws_security_group.api",type:"aws_security_group",change:{actions:["update"],before:{ingress:[]},after:{ingress:[{cidr_blocks:["0.0.0.0/0"],from_port:443,to_port:443}]}}},
        {address:"aws_lb.public_api",type:"aws_lb",change:{actions:["update"],before:{internal:true},after:{internal:false}}},
        {address:"aws_iam_role_policy.api_access",type:"aws_iam_role_policy",change:{actions:["update"],before:{},after:{}}},
        {address:"aws_s3_bucket.legacy_logs",type:"aws_s3_bucket",change:{actions:["delete"],before:{bucket:"orders-legacy-logs"},after:null}},
        {address:"aws_cloudwatch_metric_alarm.api_5xx",type:"aws_cloudwatch_metric_alarm",change:{actions:["create"],before:null,after:{alarm_name:"api-5xx"}}}
      ],
      configuration:{root_module:{resources:[
        {address:"aws_lb.public_api",expressions:{security_groups:{references:["aws_security_group.api"]}}},
        {address:"aws_db_instance.orders",expressions:{vpc_security_group_ids:{references:["aws_security_group.api"]}}},
        {address:"aws_cloudwatch_metric_alarm.api_5xx",expressions:{dimensions:{references:["aws_lb.public_api"]}}}
      ]}}
    }
  },
  revised: {
    label: "Sample: revised order service change (after review)",
    plan: {
      format_version: "1.2",
      resource_changes: [
        {address:"aws_db_instance.orders",type:"aws_db_instance",change:{actions:["update"],before:{deletion_protection:true,skip_final_snapshot:false,instance_class:"db.r6g.large"},after:{deletion_protection:true,skip_final_snapshot:false,instance_class:"db.r6g.xlarge"}}},
        {address:"aws_security_group.api",type:"aws_security_group",change:{actions:["update"],before:{ingress:[]},after:{ingress:[{cidr_blocks:["10.20.0.0/16"],from_port:443,to_port:443}]}}},
        {address:"aws_iam_role_policy.api_access",type:"aws_iam_role_policy",change:{actions:["update"],before:{},after:{}}},
        {address:"aws_s3_bucket.legacy_logs",type:"aws_s3_bucket",change:{actions:["delete"],before:{bucket:"orders-legacy-logs"},after:null}},
        {address:"aws_cloudwatch_metric_alarm.api_5xx",type:"aws_cloudwatch_metric_alarm",change:{actions:["create"],before:null,after:{alarm_name:"api-5xx"}}}
      ],
      configuration:{root_module:{resources:[
        {address:"aws_db_instance.orders",expressions:{vpc_security_group_ids:{references:["aws_security_group.api"]}}},
        {address:"aws_cloudwatch_metric_alarm.api_5xx",expressions:{dimensions:{references:["aws_lb.public_api"]}}}
      ]}}
    }
  }
};

const monitoringQuestion = "Will dashboards, alarms, and on-call responders detect a regression during rollout?";
const ownerQuestion = "Has the service owner reviewed this change and confirmed the expected user impact?";

// --- Small helpers ----------------------------------------------------------
function actionOf(actions){
  if(!Array.isArray(actions)) return "unknown";
  if(actions.includes("delete") && actions.includes("create")) return "replace";
  if(actions.includes("delete")) return "destroy";
  if(actions.includes("create")) return "create";
  if(actions.includes("update")) return "update";
  return "no-op";
}
// Terraform encodes replacement order in the action array order:
// ["create","delete"] means create-before-destroy; ["delete","create"] the reverse.
function replaceOrder(actions){
  if(!Array.isArray(actions)) return null;
  const ci=actions.indexOf("create"), di=actions.indexOf("delete");
  if(ci===-1||di===-1) return null;
  return ci<di ? "create_before_destroy" : "destroy_before_create";
}
const STATEFUL = /^(aws_db_|aws_rds_|aws_dynamodb_|aws_s3_bucket$|aws_ebs_|aws_elasticache_|aws_efs_|aws_redshift_)/;
function isStateful(type){ return STATEFUL.test(type); }

// Terraform plan JSON may render nested blocks as arrays or single objects.
// Always normalize block reads through this helper.
function asArray(x){ return Array.isArray(x)?x:x!==undefined&&x!==null?[x]:[]; }

function portLabel(from,to){
  return from===undefined||from===null?"all ports":from===to?`port ${from}`:`ports ${from}-${to}`;
}
// Returns open-to-world evidence strings with the actual CIDR cited (IPv4 vs IPv6).
function openIngress(type,value){
  if(!value || typeof value!=="object") return [];
  const evidence=[];
  const addRule=(rule)=>{
    const v4=[...(Array.isArray(rule.cidr_blocks)?rule.cidr_blocks:typeof rule.cidr_blocks==="string"?[rule.cidr_blocks]:[])];
    const v6=[...(Array.isArray(rule.ipv6_cidr_blocks)?rule.ipv6_cidr_blocks:typeof rule.ipv6_cidr_blocks==="string"?[rule.ipv6_cidr_blocks]:[])];
    const ports=portLabel(rule.from_port,rule.to_port);
    if(v4.includes("0.0.0.0/0")) evidence.push(`0.0.0.0/0 (IPv4) on ${ports}`);
    if(v6.includes("::/0")) evidence.push(`::/0 (IPv6) on ${ports}`);
  };
  // Standalone classic rule: aws_security_group_rule (only ingress matters here)
  if(type==="aws_security_group_rule"){
    if(value.type===undefined || value.type==="ingress") addRule(value);
    return evidence;
  }
  // Standalone modern rule: aws_vpc_security_group_ingress_rule
  if(type==="aws_vpc_security_group_ingress_rule"){
    const ports=portLabel(value.from_port,value.to_port);
    if(value.cidr_ipv4==="0.0.0.0/0") evidence.push(`0.0.0.0/0 (IPv4) on ${ports}`);
    if(value.cidr_ipv6==="::/0") evidence.push(`::/0 (IPv6) on ${ports}`);
    return evidence;
  }
  // Inline rules on aws_security_group and similar (blocks may be arrays or objects)
  const rules=[...asArray(value.ingress),...asArray(value.ingress_with_cidr_blocks)];
  rules.forEach(addRule);
  return evidence;
}
function becamePublic(type,before,after){
  const b=before||{}, a=after||{};
  const signals=[];
  if(b.internal!==false && a.internal===false) signals.push("load balancer scheme changed internal \u2192 internet-facing");
  if(b.publicly_accessible!==true && a.publicly_accessible===true) signals.push("publicly_accessible changed false \u2192 true");
  const beforeOpen=openIngress(type,b);
  openIngress(type,a).filter(sig=>!beforeOpen.includes(sig)).forEach(sig=>signals.push(`ingress opened to ${sig}`));
  return signals;
}

// --- Resource-specific recovery guidance ------------------------------------
// Different stateful resources need different checks. Guidance is chosen by
// resource type, never generically.
function statefulGuidance(type, action){
  const verb = action==="replace" ? "replacement" : "destruction";
  if(/^(aws_db_|aws_rds_)/.test(type)) return {
    trigger:`Database (${type}) is planned for ${verb}.`,
    impact:"A relational database holds data that recreation does not preserve. Connections drop and the endpoint may change.",
    verify:["Take a fresh manual DB snapshot immediately before apply.","Confirm automated backups / point-in-time recovery are enabled and note the retention window.","Check whether the endpoint changes and which applications hold connection strings."],
    rollback:["Restore from the pre-apply snapshot or PITR to a new instance.","Re-point applications to the restored endpoint and validate row counts against a known-good state."]
  };
  if(/^aws_s3_bucket$/.test(type)) return {
    trigger:`S3 bucket (${type}) is planned for ${verb}.`,
    impact:"Bucket deletion removes objects that are not otherwise replicated. Bucket names are globally unique and can be claimed by others after release.",
    verify:["Check whether versioning or replication is enabled and where copies exist.","Run an object inventory or at least confirm the bucket is empty of needed data.","Search for services, logs, or policies that still write to or read from this bucket."],
    rollback:["Restore objects from a replica, backup, or versioned copy if one exists.","Recreate the bucket promptly to avoid the name being claimed elsewhere \u2014 deleted objects without a copy are not recoverable."]
  };
  if(/^aws_dynamodb_/.test(type)) return {
    trigger:`DynamoDB table (${type}) is planned for ${verb}.`,
    impact:"Table data, indexes, and stream positions are lost on recreation.",
    verify:["Confirm point-in-time recovery or an on-demand backup exists.","Check for consumers of the table's streams."],
    rollback:["Restore from PITR or backup to a new table and re-point consumers."]
  };
  if(/^(aws_ebs_|aws_efs_)/.test(type)) return {
    trigger:`Storage volume/filesystem (${type}) is planned for ${verb}.`,
    impact:"Attached instances lose the data on this volume or filesystem.",
    verify:["Confirm a recent EBS snapshot or AWS Backup recovery point exists.","Identify which instances mount it and plan their downtime."],
    rollback:["Restore from the snapshot/recovery point and re-attach or re-mount."]
  };
  if(/^aws_elasticache_/.test(type)) return {
    trigger:`Cache (${type}) is planned for ${verb}.`,
    impact:"Cached data is lost; expect a cold-cache period with higher backend load and latency.",
    verify:["Confirm the backend can absorb the cache-miss load.","For Redis, check whether a final snapshot is configured if data durability matters."],
    rollback:["Recreate the cluster; warm the cache gradually or from a Redis snapshot if available."]
  };
  return {
    trigger:`Stateful resource (${type}) is planned for ${verb}.`,
    impact:"This resource may hold data that recreation does not preserve.",
    verify:["Confirm what data this resource holds and whether a backup exists."],
    rollback:["Restore from whatever backup mechanism this resource type supports."]
  };
}

// --- Risk rules -------------------------------------------------------------
const SEV = {high:3, medium:2, low:1};

function evaluate(resource){
  const {type, action, before, after, rawActions} = resource;
  const fragments=[];
  const b=before||{}, a=after||{};
  const sens=resource.afterSensitive&&typeof resource.afterSensitive==="object"?resource.afterSensitive:{};
  const isSensitive=f=>Boolean(sens[f]);

  // Tag-only updates: nothing but tags/tags_all changed. Suppress noise.
  if(action==="update"){
    const keys=new Set([...Object.keys(b),...Object.keys(a)]);
    const changedKeys=[...keys].filter(k=>JSON.stringify(b[k])!==JSON.stringify(a[k]));
    if(changedKeys.length && changedKeys.every(k=>k==="tags"||k==="tags_all")) return fragments;
  }

  const isLaunchCfg=/^aws_launch_(template|configuration)$/.test(type);
  if(action==="replace" && !isLaunchCfg){
    const order=replaceOrder(rawActions);
    const orderText=order==="create_before_destroy"
      ?"This plan creates the replacement before destroying the old resource (create-before-destroy), which reduces \u2014 but does not eliminate \u2014 downtime risk during cutover."
      :order==="destroy_before_create"
      ?"This plan destroys the existing resource before creating its replacement, so there is a window where the resource does not exist."
      :"Replacement order could not be determined from this plan.";
    fragments.push({
      severity:"high",
      trigger:`Action is replace \u2014 Terraform plans to recreate this resource. ${orderText}`,
      impact:"Depending on the resource and lifecycle configuration, expect possible downtime and loss of any state the resource holds. Dependents referencing its ID, ARN, or endpoint may break until the new resource is live.",
      verify:["Identify every resource and app config that references this resource's ID/ARN/endpoint.","Schedule a maintenance window if downtime is user-visible."],
      rollback:["Note that reverting the Terraform configuration restores the settings, not any data lost during replacement \u2014 data comes back only from backups.","First restore data from a backup/snapshot if the resource held state (see resource-specific guidance).","Then revert the Terraform change, re-apply, and re-point dependents if identifiers or endpoints changed."]
    });
  } else if(action==="destroy" && !isLaunchCfg){
    fragments.push({
      severity:"high",
      trigger:"Action is destroy \u2014 this resource is removed with no replacement.",
      impact:"Anything depending on this resource loses it once applied. If it stores data, recovery depends on whatever backups exist outside this plan.",
      verify:["Confirm nothing in production still depends on this resource."],
      rollback:["Recreate the resource from source control; data recovery depends on the resource type (see specific guidance)."]
    });
  }

  if(isStateful(type) && (action==="replace"||action==="destroy")){
    fragments.push(Object.assign({severity:"high"}, statefulGuidance(type, action)));
  }

  // Launch templates/configurations get dedicated guidance instead of the
  // generic replace/destroy fragments, so the card carries one consistent
  // rollout-focused message (no snapshot/backup advice, no absolutes).
  if(isLaunchCfg && (action==="replace"||action==="destroy")){
    const order=replaceOrder(rawActions);
    const orderText=action!=="replace"?""
      :order==="create_before_destroy"?" The plan creates the replacement before destroying the old one."
      :order==="destroy_before_create"?" The plan destroys the existing one before creating its replacement."
      :" Replacement order could not be determined from this plan.";
    fragments.push({
      severity:"medium",
      trigger:`Launch template/configuration (${type}) is planned for ${action==="replace"?"replacement":"destruction"}.${orderText}`,
      impact:"The template itself stores instance configuration. Review potential workload and data impacts separately before replacing instances. The rollout risk: Auto Scaling groups referencing it will launch new instances with the new configuration, and a bad template surfaces only as instances cycle.",
      verify:["Identify the Auto Scaling groups, fleets, and services that reference this template.","Confirm how the rollout happens (instance refresh, gradual replacement, or only new launches).","Canary or verify one instance with the new configuration before a full refresh."],
      rollback:["If only a new version was created, point the ASG back to the previous version. If the entire template is being replaced or destroyed, the previous template and its versions may no longer exist \u2014 recreate the prior configuration from source control instead.","Re-point dependents if the template ID changed, then replace any instances launched from the unwanted configuration."]
    });
  }

  if(b.deletion_protection===true && a.deletion_protection===false){
    fragments.push({
      severity:"high",
      trigger:"deletion_protection changed true \u2192 false.",
      impact:"The guardrail preventing accidental deletion is being removed, often as a precursor to replacing or destroying a database.",
      verify:["Confirm turning off deletion protection is intentional and time-boxed.","Ensure a final snapshot / backup is guaranteed before any delete."],
      rollback:["Re-enable deletion_protection immediately after the change completes."]
    });
  }
  if(a.skip_final_snapshot===true && b.skip_final_snapshot!==true && /^(aws_db_|aws_rds_)/.test(type)){
    fragments.push({
      severity:"high",
      trigger:"skip_final_snapshot changed to true.",
      impact:"If this database is deleted or replaced, Terraform will not take a final snapshot \u2014 recovery would then depend entirely on other backups (automated snapshots, PITR, or manual copies).",
      verify:["Take a manual snapshot yourself before apply.","Reconsider whether skip_final_snapshot should be false for this change."],
      rollback:["Restore from your manual snapshot (the automatic final snapshot will not exist)."]
    });
  }

  // Backup / retention reductions (RDS, ElastiCache snapshots, log groups).
  const retentionFields=[["backup_retention_period","automated backup retention","recovery"],["snapshot_retention_limit","snapshot retention","recovery"],["retention_in_days","log retention","history"]];
  retentionFields.forEach(([field,label,kind])=>{
    const bv=b[field], av=a[field];
    if(typeof bv==="number" && typeof av==="number" && av<bv){
      const narrowImpact=kind==="history"
        ?`Shorter ${label} shortens the investigation and audit history available after an incident.`
        :`Shorter ${label} narrows the recovery window after an incident.`;
      const zeroImpact=kind==="history"
        ?`With ${label} disabled, no history is retained for investigation or audit beyond what is exported elsewhere.`
        :`With ${label} disabled, recovery for this resource depends entirely on backups taken outside this configuration.`;
      fragments.push({
        severity:av===0?"high":"medium",
        trigger:`${field} reduced ${bv} \u2192 ${av}${av===0?" \u2014 "+label+" disabled":""}.`,
        impact:av===0?zeroImpact:narrowImpact,
        verify:[kind==="history"?`Confirm the reduced ${label} still meets incident-investigation and audit requirements.`:`Confirm the reduced ${label} still meets the recovery-point objective for this service.`,"Check whether any compliance requirement mandates the previous retention."],
        rollback:[`Restore ${field} to ${bv}; note that history already aged out during the shorter window is not recovered.`]
      });
    }
  });

  // Encryption being disabled.
  [["storage_encrypted","storage encryption"],["encrypted","encryption"]].forEach(([field,label])=>{
    if(b[field]===true && a[field]===false){
      fragments.push({
        severity:"high",
        trigger:`${field} changed true \u2192 false.`,
        impact:`Data ${label} at rest is being turned off. For many resources this forces a replacement, and new data will be stored unencrypted.`,
        verify:["Confirm disabling encryption is intentional \u2014 it rarely is.","Check compliance requirements (most mandate encryption at rest)."],
        rollback:[`Re-enable ${field}; data written while unencrypted may need re-encryption or migration.`]
      });
    }
  });

  // High-availability downgrade.
  if(b.multi_az===true && a.multi_az===false){
    fragments.push({
      severity:"medium",
      trigger:"multi_az changed true \u2192 false.",
      impact:"The database loses its standby replica. An availability-zone failure or maintenance event now means downtime instead of automatic failover.",
      verify:["Confirm the availability trade-off is acceptable for this workload.","Check whether maintenance windows will now cause user-visible downtime."],
      rollback:["Re-enable multi_az; conversion runs online but takes time to provision the standby."]
    });
  }

  // Audit trail disabled.
  if(/^aws_cloudtrail/.test(type) && b.enable_logging!==false && a.enable_logging===false){
    fragments.push({
      severity:"high",
      trigger:"enable_logging changed to false on a CloudTrail trail.",
      impact:"API activity stops being recorded. Security investigations and compliance audits lose visibility from the moment this applies.",
      verify:["Confirm the logging pause is intentional and time-boxed.","Check whether another trail or organization trail still covers these events."],
      rollback:["Re-enable logging; events during the gap are not recoverable."]
    });
  }

  // Route / NAT removal severs connectivity.
  if((/^aws_(route$|nat_gateway|internet_gateway)/.test(type)) && (action==="destroy")){
    fragments.push({
      severity:"medium",
      trigger:`Connectivity resource (${type}) is being destroyed.`,
      impact:"Traffic that depended on this route or gateway will fail after apply \u2014 typically outbound internet access or cross-network paths.",
      verify:["Identify subnets and workloads that route through this resource.","Confirm an alternative path exists or the connectivity is genuinely unused."],
      rollback:["Recreate the route/gateway; NAT gateways take several minutes to provision."]
    });
  }

  // Availability: service scaled to zero.
  if(typeof b.desired_count==="number" && a.desired_count===0 && b.desired_count>0){
    fragments.push({
      severity:"high",
      trigger:`desired_count reduced ${b.desired_count} \u2192 0.`,
      impact:"The service will run zero tasks after apply \u2014 an availability outage for anything it serves, even though the resource itself still exists.",
      verify:["Confirm an intentional shutdown or migration is in progress.","Check what consumes this service and how it degrades."],
      rollback:["Restore the previous desired_count and wait for tasks to become healthy."]
    });
  }

  // Monitoring silenced.
  if(b.actions_enabled!==false && a.actions_enabled===false && /^aws_cloudwatch_metric_alarm/.test(type)){
    fragments.push({
      severity:"medium",
      trigger:"actions_enabled changed to false on a CloudWatch alarm.",
      impact:"The alarm still evaluates but no longer notifies or triggers actions \u2014 a regression during rollout may go unnoticed.",
      verify:["Confirm the silence is intentional and time-boxed (e.g., during a migration).","Ensure another alerting path covers this signal meanwhile."],
      rollback:["Re-enable alarm actions immediately after the change window."]
    });
  }

  // S3 public-access controls being disabled.
  if(type==="aws_s3_bucket_public_access_block"){
    const flags=["block_public_acls","block_public_policy","ignore_public_acls","restrict_public_buckets"];
    const weakened=flags.filter(f=>b[f]===true && a[f]===false);
    const removed=action==="destroy";
    if(weakened.length||removed){
      fragments.push({
        severity:"high",
        trigger:removed?"Public access block is being deleted from the bucket.":`Public access block weakened \u2014 ${weakened.map(f=>`${f} true \u2192 false`).join(", ")}.`,
        impact:"The guardrail preventing public bucket ACLs/policies is being removed. Combined with a permissive policy, bucket contents could become publicly readable.",
        verify:["Confirm the bucket policy and ACLs that will now take effect.","Verify no object in the bucket must remain private."],
        rollback:["Re-enable all four public access block settings.","Audit access logs for anonymous reads during the exposure window."]
      });
    }
  }

  // Bucket policy granting anonymous access.
  if(/^aws_s3_bucket_policy$/.test(type) && action!=="destroy"){
    const anon=policyAllowsAnonymous(a.policy);
    if(anon && !policyAllowsAnonymous(b.policy)){
      fragments.push({
        severity:"high",
        trigger:`Bucket policy adds an Allow statement with Principal "*"${anon.actions&&!isSensitive("policy")?` for ${anon.actions}`:""}.${isSensitive("policy")?" The policy is marked sensitive, so its contents are not repeated in this report.":""}`,
        impact:"This statement would permit anonymous requests for the granted actions on matching objects. Whether requests actually succeed also depends on the bucket's public access block, ACLs, and any deny statements.",
        verify:["Confirm anonymous access is intended (e.g., a public website bucket) and scoped to exactly the right prefix.","Check that no sensitive objects share this bucket."],
        rollback:["Remove or scope the anonymous statement.","Audit S3 access logs for anonymous requests during the window."]
      });
    }
  }

  // S3 lifecycle expiration shortened. Terraform plan JSON may render `rule`
  // and `expiration` as arrays or single objects; handle both, plus the
  // legacy inline `lifecycle_rule` on aws_s3_bucket.
  if(/^(aws_s3_bucket_lifecycle_configuration|aws_s3_bucket)$/.test(type) && action!=="destroy"){
    const asArray=x=>Array.isArray(x)?x:x?[x]:[];
    const days=cfg=>[...asArray(cfg?.rule),...asArray(cfg?.lifecycle_rule)]
      .flatMap(r=>asArray(r?.expiration))
      .map(e=>e?.days)
      .filter(d=>typeof d==="number"&&d>0);
    const bMin=Math.min(...days(b),Infinity), aMin=Math.min(...days(a),Infinity);
    if(aMin<bMin && aMin!==Infinity){
      fragments.push({
        severity:"medium",
        trigger:`Lifecycle expiration shortened \u2014 minimum expiration days ${bMin===Infinity?"unset":bMin} \u2192 ${aMin}.`,
        impact:"Objects will be deleted sooner. Data older than the new window is removed on the next lifecycle run and is not recoverable without versioning or backups.",
        verify:["Confirm the shorter retention meets audit and recovery requirements.","Check whether versioning or replication preserves expired objects."],
        rollback:["Restore the previous expiration; objects already expired are not recovered."]
      });
    }
  }

  // Public exposure with accurate IPv4/IPv6 evidence, incl. standalone rules.
  if(["create","replace","update"].includes(action)){
    const signals=becamePublic(type,before,after);
    if(signals.length){
      fragments.push({
        severity:"high",
        trigger:`Access scope widens \u2014 ${signals.join("; ")}.`,
        impact:"This change permits broader access than before. Actual internet reachability also depends on routing, NACLs, other security groups, and whether the resource has a public address \u2014 but the permissive setting takes effect immediately on apply.",
        verify:["Confirm public exposure is intended for this resource.","Check that authentication, WAF, and least-privilege security groups are in place.","Scope CIDR ranges to known clients instead of 0.0.0.0/0 or ::/0 where possible."],
        rollback:["Revert the scheme/ingress change to restore private access.","Rotate anything that may have been exposed during the window."]
      });
    }
  }

  if(/^aws_iam_/.test(type) && action!=="destroy"){
    const wild=policyWildcard(a.policy)||policyWildcard(a.assume_role_policy)||policyWildcard(a.inline_policy);
    if(wild && !(policyWildcard(b.policy)||policyWildcard(b.assume_role_policy)||policyWildcard(b.inline_policy))){
      fragments.push({
        severity:"high",
        trigger:`IAM policy expands to ${wild} \u2014 an administrative-scope grant.`,
        impact:"Principals attached to this policy would be granted the wildcarded actions on the wildcarded resources \u2014 far broader than most workloads need. Actual effective access also depends on permissions boundaries, SCPs, and explicit denies.",
        verify:["Replace wildcards with the specific actions and resource ARNs the workload uses.","If a wildcard is genuinely required, document why and add a permissions boundary or SCP guardrail."],
        rollback:["Re-apply the previous policy document from source control \u2014 IAM changes take effect quickly in both directions."]
      });
    } else {
      fragments.push({
        severity:"medium",
        trigger:`IAM resource (${type}) is changing (${action}). No wildcard grant was detected by the supported checks; review the full policy diff.`,
        impact:"Permission or trust changes can silently over-grant access or break a workload that relied on the old policy.",
        verify:["Diff the effective permissions and trust relationships against the previous policy.","Confirm the change follows least privilege; test the workload with the new policy in a non-production account if possible."],
        rollback:["Re-apply the previous policy document from source control \u2014 IAM changes take effect quickly in both directions."]
      });
    }
  }

  if(/^aws_(security_group|vpc_security_group|route|vpc|subnet|network_acl)/.test(type) && !becamePublic(type,before,after).length){
    fragments.push({
      severity:"medium",
      trigger:`Network resource (${type}) is changing (${action}). No exposure pattern was detected by the supported checks \u2014 this does not rule out exposure via fields the analyzer does not inspect.`,
      impact:"This is a connectivity-review concern: traffic paths between services can change, causing connectivity failures that only surface at runtime.",
      verify:["Trace which services rely on the affected routes / rules.","Review the raw diff for exposure in fields beyond inline/standalone ingress CIDRs.","Test connectivity from dependent services after apply."],
      rollback:["Restore the previous network configuration and re-test paths."]
    });
  }

  return fragments;
}

// Detect Allow statements with Principal "*" in an S3 bucket policy (string or object).
function policyAllowsAnonymous(policy){
  const doc=parsePolicy(policy);
  if(!doc) return null;
  const stmts=Array.isArray(doc.Statement)?doc.Statement:doc.Statement?[doc.Statement]:[];
  for(const s of stmts){
    const principal=s.Principal;
    const anon=principal==="*"||(principal&&principal.AWS==="*");
    if(s.Effect==="Allow"&&anon){
      const actions=Array.isArray(s.Action)?s.Action.join(", "):s.Action;
      return {actions};
    }
  }
  return null;
}
// Detect Action:"*" together with Resource:"*" in an IAM policy document.
function policyWildcard(policy){
  const doc=parsePolicy(policy);
  if(!doc) return null;
  const stmts=Array.isArray(doc.Statement)?doc.Statement:doc.Statement?[doc.Statement]:[];
  for(const s of stmts){
    if(s.Effect!=="Allow") continue;
    const acts=Array.isArray(s.Action)?s.Action:[s.Action];
    const res=Array.isArray(s.Resource)?s.Resource:[s.Resource];
    const actWild=acts.includes("*"), resWild=res.includes("*");
    if(actWild&&resWild) return 'Action: "*" on Resource: "*"';
    if(actWild) return 'Action: "*"';
  }
  return null;
}
function parsePolicy(policy){
  if(!policy) return null;
  if(typeof policy==="object") return policy;
  if(typeof policy==="string"){ try{ return JSON.parse(policy); }catch(e){ return null; } }
  return null;
}

// --- Dependency reference list ----------------------------------------------
// Derived only from configuration references present in the supplied plan,
// including child modules. Module-relative references are qualified with the
// module path so they match resource_changes addresses. Anything the plan
// does not state is explicitly reported as unknown.
function buildDependencies(plan, resources){
  const changed=new Set(resources.map(r=>r.address));
  const edges=[];
  function qualify(prefix, ref){
    // Trim index/attribute suffixes down to type.name (or module.X.type.name).
    const parts=ref.split(".");
    let base;
    if(parts[0]==="module"&&parts.length>=4) base=parts.slice(0,4).join(".");
    else if(parts[0]==="module") return null; // module output ref, not a resource
    else if(parts[0]==="var"||parts[0]==="local"||parts[0]==="data"||parts[0]==="each"||parts[0]==="count") return null;
    else base=parts.slice(0,2).join(".");
    return prefix?`${prefix}.${base}`:base;
  }
  function walk(mod, prefix){
    (mod?.resources||[]).forEach(res=>{
      const from=prefix?`${prefix}.${res.address}`:res.address;
      const refs=new Set();
      (function collect(expr){
        if(!expr || typeof expr!=="object") return;
        if(Array.isArray(expr)){ expr.forEach(collect); return; }
        if(Array.isArray(expr.references)) expr.references.forEach(ref=>{
          const target=qualify(prefix, ref);
          if(target && target!==from) refs.add(target);
        });
        Object.values(expr).forEach(collect);
      })(res.expressions);
      refs.forEach(to=>edges.push({from,to}));
    });
    Object.entries(mod?.module_calls||{}).forEach(([name,call])=>{
      walk(call.module, prefix?`${prefix}.module.${name}`:`module.${name}`);
    });
  }
  walk(plan.configuration?.root_module, "");
  // Keep edges where at least one side is changing.
  const relevant=edges.filter(e=>changed.has(e.from)||changed.has(e.to));
  const known=new Set();
  relevant.forEach(e=>{known.add(e.from);known.add(e.to);});
  const unknown=resources.map(r=>r.address).filter(a=>!known.has(a));
  return {
    edges:relevant,
    unknown,
    hasConfig:Boolean(plan.configuration?.root_module)
  };
}

// Fields relevant to our checks that are unknown until apply or masked as
// sensitive. The analyzer must say so instead of silently treating them as absent.
const WATCHED_FIELDS=["deletion_protection","skip_final_snapshot","backup_retention_period","snapshot_retention_limit","retention_in_days","desired_count","actions_enabled","internal","publicly_accessible","ingress","cidr_blocks","ipv6_cidr_blocks","cidr_ipv4","cidr_ipv6","policy","multi_az","storage_encrypted","encrypted","enable_logging","block_public_acls","block_public_policy","ignore_public_acls","restrict_public_buckets","rule","lifecycle_rule"];
function unknownFields(obj){
  if(!obj||typeof obj!=="object") return [];
  const NOISE=new Set(["id","arn","tags_all","unique_id"]);
  return Object.keys(obj).filter(f=>{
    if(NOISE.has(f)) return false;
    const v=obj[f];
    return v===true||(v&&typeof v==="object"&&(Array.isArray(v)?v.some(x=>x===true||(x&&typeof x==="object"&&Object.keys(x).length)):Object.keys(v).length));
  });
}
function unknownCaveats(resource){
  const caveats=[];
  unknownFields(resource.afterUnknown).forEach(f=>{
    const watched=WATCHED_FIELDS.includes(f);
    caveats.push(`${f} is not known until apply \u2014 ${watched?"the related checks could not evaluate its final value; review at apply time.":"its final value cannot be reviewed from this plan."}`);
  });
  unknownFields(resource.afterSensitive).forEach(f=>{
    const present=resource.after&&typeof resource.after==="object"&&resource.after[f]!==undefined&&resource.after[f]!==null;
    caveats.push(present
      ?`${f} is marked sensitive \u2014 the value is present in the plan and was analyzed by the supported checks, but it is not shown in this report. Redaction covers this report's output only, not the plan file itself.`
      :`${f} is marked sensitive and its value is absent from this plan \u2014 it could not be analyzed; review it at apply time.`);
  });
  return [...new Set(caveats)];
}

// Coverage disclosure: exactly what this analyzer checks. Shown in the UI and
// the exported brief so reviewers know what was NOT examined.
const CHECKS=[
  "Destroy / replace actions, with create-before-destroy vs destroy-before-create ordering",
  "Stateful resources (RDS, S3, DynamoDB, EBS/EFS, ElastiCache, Redshift) with type-specific recovery guidance",
  "deletion_protection and skip_final_snapshot changes",
  "Backup/snapshot/log retention reductions (backup_retention_period, snapshot_retention_limit, retention_in_days)",
  "Open ingress (0.0.0.0/0, ::/0) on inline and standalone security-group rules, IPv4 and IPv6",
  "Load balancer scheme and publicly_accessible changes",
  "S3 public access block weakening, anonymous-principal bucket policies, lifecycle expiration shortening",
  "IAM wildcard grants (Action/Resource \"*\") and other IAM changes",
  "Encryption disabled (storage_encrypted, encrypted), multi_az downgrade, CloudTrail logging disabled",
  "ECS desired_count scaled to zero, CloudWatch alarm actions disabled",
  "Route / NAT / internet gateway deletion",
  "Fields unknown-until-apply are reported, not silently skipped. Sensitive-marked fields are analyzed when their value is present in the plan and are redacted from this report's output; redaction of the plan file itself is out of scope"
];

// Severity-weighted risk score, 0-10. A communication aid, not a safety metric.
function riskScore(cards){
  const raw=cards.reduce((s,c)=>s+(c.severity==="high"?3:c.severity==="medium"?1:0.5),0);
  return Math.min(10,Math.round(raw*10)/10);
}

function analyze(plan){
  if(!plan || !Array.isArray(plan.resource_changes)) throw new Error("This is not a Terraform JSON plan with resource_changes. Run terraform show -json tfplan > plan.json.");
  if(plan.resource_changes.length>10000) throw new Error("This plan is too large for the browser review (10,000 resource changes maximum).");
  const resources=plan.resource_changes
    .map(item=>({address:String(item.address||"Unknown resource"),type:String(item.type||""),action:actionOf(item.change?.actions),rawActions:item.change?.actions,before:item.change?.before,after:item.change?.after,afterUnknown:item.change?.after_unknown,afterSensitive:item.change?.after_sensitive}))
    .filter(item=>item.action!=="no-op");

  const cards=[];
  resources.forEach(r=>{
    const fragments=evaluate(r);
    if(!fragments.length) return;
    const severity=fragments.reduce((s,f)=>SEV[f.severity]>SEV[s]?f.severity:s,"low");
    const caveats=unknownCaveats(r);
    cards.push({
      address:r.address, type:r.type, action:r.action, severity,
      triggers:fragments.map(f=>f.trigger),
      impacts:[...new Set(fragments.map(f=>f.impact))],
      verify:[...new Set(fragments.flatMap(f=>f.verify))],
      rollback:[...new Set(fragments.flatMap(f=>f.rollback))],
      caveats
    });
  });
  cards.sort((x,y)=>SEV[y.severity]-SEV[x.severity]);

  const questions=[...new Set(cards.flatMap(c=>c.verify).slice(0,3)),monitoringQuestion,ownerQuestion].slice(0,5);
  const dependencies=buildDependencies(plan, resources);
  const unknowns=resources
    .map(r=>({address:r.address,caveats:unknownCaveats(r)}))
    .filter(u=>u.caveats.length);
  return {resources,cards,questions,dependencies,unknowns,score:riskScore(cards),checks:CHECKS};
}

// --- Plan comparison --------------------------------------------------------
// Compares findings by resource address + trigger. Reports which detected
// risks disappear in the revised plan and which remain. Never claims safety.
function compareReports(baseReport, revisedReport){
  const key=(card,trigger)=>`${card.address} :: ${trigger}`;
  const baseKeys=new Map();
  baseReport.cards.forEach(c=>c.triggers.forEach(t=>baseKeys.set(key(c,t),{address:c.address,trigger:t,severity:c.severity})));
  const revisedKeys=new Set();
  revisedReport.cards.forEach(c=>c.triggers.forEach(t=>revisedKeys.add(key(c,t))));
  const resolved=[],remaining=[];
  baseKeys.forEach((v,k)=>{ (revisedKeys.has(k)?remaining:resolved).push(v); });
  const added=[];
  revisedReport.cards.forEach(c=>c.triggers.forEach(t=>{ if(!baseKeys.has(key(c,t))) added.push({address:c.address,trigger:t,severity:c.severity}); }));
  return {resolved,remaining,added};
}

// --- Markdown review brief --------------------------------------------------
function toMarkdown(report,name,comparison,baseName){
  const lines=[];
  lines.push(`# BlastRadius review brief`,``,`**Plan:** ${name}`,`**Generated:** ${new Date().toISOString()}`,``);
  const counts={create:0,update:0,destroy:0,replace:0};
  report.resources.forEach(r=>{if(counts[r.action]!==undefined)counts[r.action]++;});
  lines.push(`## Summary`,``,`| Changing | Create | Update | Destroy/Replace | Risk score |`,`|---|---|---|---|---|`,`| ${report.resources.length} | ${counts.create} | ${counts.update} | ${counts.destroy+counts.replace} | ${report.score}/10 |`,``);
  lines.push(`*The risk score is a severity-weighted communication aid, not a safety metric.*`,``);
  lines.push(`## Flagged resources (${report.cards.length})`,``);
  if(!report.cards.length) lines.push(`No priority risk pattern detected. This does not prove the change is safe; review the full diff.`,``);
  report.cards.forEach(c=>{
    lines.push(`### ${c.severity.toUpperCase()} \u2014 \`${c.address}\` (${c.action})`,``);
    lines.push(`**Evidence:**`);
    c.triggers.forEach(t=>lines.push(`- ${t}`));
    lines.push(``,`**Likely impact:**`);
    c.impacts.forEach(t=>lines.push(`- ${t}`));
    if(c.caveats && c.caveats.length){
      lines.push(``,`**Not evaluable from this plan:**`);
      c.caveats.forEach(t=>lines.push(`- ${t}`));
    }
    lines.push(``,`**Verify before apply:**`);
    c.verify.forEach(t=>lines.push(`- [ ] ${t}`));
    lines.push(``,`**Rollback plan:**`);
    c.rollback.forEach(t=>lines.push(`- ${t}`));
    lines.push(``);
  });
  lines.push(`## Dependency evidence`,``);
  if(report.dependencies.edges.length){
    report.dependencies.edges.forEach(e=>lines.push(`- \`${e.from}\` references \`${e.to}\``));
  } else {
    lines.push(`- No reference edges could be derived from this plan file.`);
  }
  if(report.dependencies.unknown.length){
    lines.push(``,`**Unknown from this plan** (no configuration references available \u2014 verify manually):`);
    report.dependencies.unknown.forEach(a=>lines.push(`- \`${a}\``));
  }
  lines.push(``);
  lines.push(`## Not evaluable from this plan`,``);
  if(report.unknowns.length){
    lines.push(`These fields are unknown until apply or marked sensitive. Unknown values could not be reviewed; sensitive values are analyzed when present in the plan but redacted from this report:`,``);
    report.unknowns.forEach(u=>{
      lines.push(`- \`${u.address}\``);
      u.caveats.forEach(c=>lines.push(`  - ${c}`));
    });
  } else {
    lines.push(`No unknown-until-apply or sensitive-masked fields were reported in this plan.`);
  }
  lines.push(``);
  if(comparison){
    lines.push(`## Comparison vs ${baseName}`,``,`Result is reported as *fewer detected risks*, not a guarantee of safety.`,``);
    lines.push(`**Resolved findings (${comparison.resolved.length}):**`);
    comparison.resolved.forEach(f=>lines.push(`- ~~${f.address}: ${f.trigger}~~`));
    lines.push(``,`**Remaining findings (${comparison.remaining.length}):**`);
    comparison.remaining.forEach(f=>lines.push(`- ${f.address}: ${f.trigger}`));
    if(comparison.added.length){
      lines.push(``,`**New findings (${comparison.added.length}):**`);
      comparison.added.forEach(f=>lines.push(`- ${f.address}: ${f.trigger}`));
    }
    lines.push(``);
  }
  lines.push(`## Open review questions`,``);
  report.questions.forEach(q=>lines.push(`- [ ] ${q}`));
  lines.push(``,`## Coverage \u2014 what this review checked`,``,`This analyzer runs a fixed set of deterministic checks. Anything outside this list was not examined:`,``);
  report.checks.forEach(c=>lines.push(`- ${c}`));
  lines.push(``,`---`,`*Generated by BlastRadius. Deterministic review aid based on the plan file only; it cannot prove a change is safe.*`,``);
  return lines.join("\n");
}

// --- Rendering --------------------------------------------------------------
function node(tag,cls,value){const el=document.createElement(tag);if(cls)el.className=cls;if(value!==undefined)el.textContent=value;return el;}
function list(items){const ul=node("ul","checklist");items.forEach(i=>ul.append(node("li",null,i)));return ul;}

function riskCard(card){
  const el=node("article",`risk-card ${card.severity}`);
  const head=node("div","risk-head");
  head.append(node("code",null,card.address),node("span",`action ${card.action}`,card.action.toUpperCase()),node("span",`tag ${card.severity}`,card.severity.toUpperCase()));
  el.append(head);
  const trig=node("div","risk-block");
  trig.append(node("h4",null,"Evidence \u2014 what triggered this"),list(card.triggers));
  el.append(trig);
  const imp=node("div","risk-block");
  imp.append(node("h4",null,"Likely service impact"));
  card.impacts.forEach(t=>imp.append(node("p",null,t)));
  el.append(imp);
  const cols=node("div","risk-cols");
  const v=node("div","risk-block");
  v.append(node("h4",null,"Verify before apply"),list(card.verify));
  const rb=node("div","risk-block");
  rb.append(node("h4",null,"Rollback plan"),list(card.rollback));
  cols.append(v,rb);
  el.append(cols);
  if(card.caveats&&card.caveats.length){
    const cv=node("div","risk-block caveats");
    cv.append(node("h4",null,"Not evaluable from this plan"),list(card.caveats));
    el.append(cv);
  }
  return el;
}

let currentReport=null, currentName="", baseReport=null, baseName="", currentComparison=null;

function renderDependencies(dep){
  const box=$("dependencies");
  const parts=[];
  if(dep.edges.length){
    const ul=node("ul","dep-list");
    dep.edges.forEach(e=>{
      const li=node("li");
      li.append(node("code",null,e.from),node("span","dep-arrow"," \u2192 references \u2192 "),node("code",null,e.to));
      ul.append(li);
    });
    parts.push(ul);
  } else {
    parts.push(node("p","dep-note",dep.hasConfig?"No reference edges among changing resources were found in this plan.":"This plan file does not include a configuration section, so no dependency edges can be derived."));
  }
  if(dep.unknown.length){
    const p=node("p","dep-note");
    p.append(node("strong",null,"Unknown from this plan: "),document.createTextNode(dep.unknown.join(", ")+". Relationships for these resources cannot be established from the supplied plan \u2014 verify manually."));
    parts.push(p);
  }
  box.replaceChildren(...parts);
}

function renderComparison(comparison, revisedLabel){
  const box=$("comparison"); const wrap=$("comparison-panel");
  if(!comparison){ wrap.hidden=true; return; }
  wrap.hidden=false;
  const mk=(title,items,cls)=>{
    const d=node("div","cmp-block");
    d.append(node("h4",null,`${title} (${items.length})`));
    if(items.length){
      const ul=node("ul","checklist "+cls);
      items.forEach(f=>{const li=node("li");li.append(node("code",null,f.address),document.createTextNode(" \u2014 "+f.trigger));ul.append(li);});
      d.append(ul);
    } else d.append(node("p","dep-note","None."));
    return d;
  };
  const note=node("p","dep-note",`Comparing ${revisedLabel} against ${baseName}. Result means fewer detected risks \u2014 not a guarantee of safety.`);
  box.replaceChildren(note,mk("Resolved findings",comparison.resolved,"cmp-resolved"),mk("Remaining findings",comparison.remaining,"cmp-remaining"),mk("New findings",comparison.added,"cmp-added"));
}

function render(plan,name,{asComparison=false}={}){
  const report=analyze(plan);
  if(asComparison && baseReport){
    currentComparison=compareReports(baseReport,report);
  } else {
    baseReport=report; baseName=name; currentComparison=null;
  }
  currentReport=report; currentName=name;

  const rs=report.resources,counts={create:0,update:0,destroy:0,replace:0};
  rs.forEach(r=>{if(counts[r.action]!==undefined)counts[r.action]++;});
  $("total").textContent=rs.length;$("creates").textContent=counts.create;$("updates").textContent=counts.update;$("destructive").textContent=counts.destroy+counts.replace;
  $("filename").textContent=name;$("resource-count").textContent=`${rs.length} changes`;

  const highest=report.cards.length?report.cards[0].severity:"low";
  const highCount=report.cards.filter(c=>c.severity==="high").length;
  const verdict=$("verdict");verdict.className=`verdict ${highest}`;
  verdict.replaceChildren(node("span","verdict-icon",highest==="high"?"\u26a0":highest==="medium"?"\u25c8":"\u2713"));
  const copy=node("div");
  copy.append(
    node("b",null,highest==="high"?"High attention change":highest==="medium"?"Review recommended":"Standard review"),
    node("p",null,(highest==="high"?`${highCount} resource${highCount===1?"":"s"} could cause downtime, data loss, or exposure. Pause for a focused review before apply.`:highest==="medium"?"Some changes need a closer look before apply.":"No priority patterns detected. Still review the full diff before applying.")+` Risk score: ${report.score}/10 (severity-weighted across supported checks).`)
  );
  verdict.append(copy);

  $("risk-count").textContent=report.cards.length?`${report.cards.length} resource${report.cards.length===1?"":"s"} flagged`:"no resources flagged";
  if(report.cards.length){
    $("risk-cards").replaceChildren(...report.cards.map(riskCard));
  }else{
    const ok=node("div","risk-empty");
    ok.append(node("strong",null,"No priority risk pattern detected"),node("p",null,"This plan shows no destructive, exposure, or data-loss patterns. Confirm intent and validate service-specific behavior before applying."));
    $("risk-cards").replaceChildren(ok);
  }

  renderDependencies(report.dependencies);
  renderComparison(currentComparison,name);

  const cov=$("coverage");
  if(cov) cov.replaceChildren(...report.checks.map(c=>node("li",null,c)));
  const unk=$("plan-unknowns");
  if(unk){
    if(report.unknowns.length){
      const items=report.unknowns.flatMap(u=>u.caveats.map(c=>`${u.address}: ${c}`));
      unk.replaceChildren(node("p","dep-note","These fields are unknown until apply or marked sensitive. Unknown values could not be reviewed; sensitive values are analyzed when present in the plan but redacted from this report:"),list(items));
    } else {
      unk.replaceChildren(node("p","dep-note","No unknown-until-apply or sensitive-masked fields were reported in this plan."));
    }
  }

  $("questions").replaceChildren(...report.questions.map(q=>node("li",null,q)));
  $("resource-list").replaceChildren(...rs.map(r=>{const el=node("div","resource");el.append(node("code",null,r.address),node("span",`action ${r.action}`,r.action.toUpperCase()));return el;}));

  $("empty").hidden=true;$("error").hidden=true;$("results").hidden=false;$("workspace").scrollIntoView({behavior:"smooth",block:"start"});
}

function fail(message){$("error").textContent=message;$("error").hidden=false;}

function exportBrief(){
  if(!currentReport) return;
  const md=toMarkdown(currentReport,currentName,currentComparison,baseName);
  const blob=new Blob([md],{type:"text/markdown"});
  const a=document.createElement("a");
  a.href=URL.createObjectURL(blob);
  a.download="blastradius-review-brief.md";
  a.click();
  URL.revokeObjectURL(a.href);
}

$("sample-risky").addEventListener("click",()=>render(samples.risky.plan,samples.risky.label));
$("sample-revised").addEventListener("click",()=>{
  if(!baseReport) render(samples.risky.plan,samples.risky.label);
  render(samples.revised.plan,samples.revised.label,{asComparison:true});
});
$("sample-safe").addEventListener("click",()=>render(samples.safe.plan,samples.safe.label));
$("export").addEventListener("click",exportBrief);

async function readPlanFile(file){
  if(file.size>10*1024*1024) throw new Error("The file exceeds the 10 MB limit.");
  try{ return JSON.parse(await file.text()); }
  catch(e){ throw new Error("The selected file is not valid JSON."); }
}
$("file").addEventListener("change",async event=>{
  const file=event.target.files?.[0];if(!file)return;
  try{render(await readPlanFile(file),file.name);}catch(error){fail(error.message);}finally{event.target.value="";}
});
$("file-compare").addEventListener("change",async event=>{
  const file=event.target.files?.[0];if(!file)return;
  if(!baseReport){fail("Load a base plan first, then compare a revised plan against it.");event.target.value="";return;}
  try{render(await readPlanFile(file),file.name,{asComparison:true});}catch(error){fail(error.message);}finally{event.target.value="";}
});
