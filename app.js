"use strict";
// All plan processing stays in the browser. Never render raw plan values or sensitive fields.
const $ = id => document.getElementById(id);

// --- Demo plans -------------------------------------------------------------
// Three plans tell one story: a risky agent-proposed change, the engineer's
// revised version, and a routine safe deploy. Each includes a configuration
// block so the dependency map can be derived from real references.
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
const STATEFUL = /^(aws_db_|aws_rds_|aws_dynamodb_|aws_s3_bucket$|aws_ebs_|aws_elasticache_|aws_efs_|aws_redshift_)/;
function isStateful(type){ return STATEFUL.test(type); }

function openCidrs(value){
  // Inspect recognized network fields only. Never serialize or show secrets.
  if(!value || typeof value!=="object") return [];
  const rules=[...(Array.isArray(value.ingress)?value.ingress:[]),...(Array.isArray(value.ingress_with_cidr_blocks)?value.ingress_with_cidr_blocks:[])];
  const ports=[];
  rules.forEach(rule=>{
    const blocks=[...(Array.isArray(rule.cidr_blocks)?rule.cidr_blocks:[]),...(Array.isArray(rule.ipv6_cidr_blocks)?rule.ipv6_cidr_blocks:[])];
    if(typeof rule.cidr_blocks==="string") blocks.push(rule.cidr_blocks);
    if(blocks.includes("0.0.0.0/0")||blocks.includes("::/0")){
      const from=rule.from_port, to=rule.to_port;
      ports.push(from===undefined?"all ports":from===to?`port ${from}`:`ports ${from}-${to}`);
    }
  });
  return ports;
}
function becamePublic(before,after){
  const b=before||{}, a=after||{};
  const signals=[];
  if(b.internal!==false && a.internal===false) signals.push("load balancer scheme changed internal \u2192 internet-facing");
  if(b.publicly_accessible!==true && a.publicly_accessible===true) signals.push("publicly_accessible changed false \u2192 true");
  const newPorts=openCidrs(a).filter(p=>!openCidrs(b).includes(p));
  if(newPorts.length) signals.push(`ingress opened to 0.0.0.0/0 on ${newPorts.join(", ")}`);
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
  const {type, action, before, after} = resource;
  const fragments=[];

  if(action==="replace"){
    fragments.push({
      severity:"high",
      trigger:"Action is replace \u2014 Terraform plans to recreate this resource. Unless create_before_destroy is set, the existing resource is destroyed before its replacement exists.",
      impact:"Depending on the resource and lifecycle configuration, expect possible downtime and loss of any state the resource holds. Dependents referencing its ID, ARN, or endpoint may break until the new resource is live.",
      verify:["Identify every resource and app config that references this resource's ID/ARN/endpoint.","Schedule a maintenance window if downtime is user-visible."],
      rollback:["Revert the Terraform change and re-apply the previous configuration.","Re-point dependents if identifiers changed."]
    });
  } else if(action==="destroy"){
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

  const b=before||{}, a=after||{};
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

  if(["create","replace","update"].includes(action)){
    const signals=becamePublic(before,after);
    if(signals.length){
      fragments.push({
        severity:"high",
        trigger:`Gains public reachability \u2014 ${signals.join("; ")}.`,
        impact:"This resource may become reachable from the internet. Combined with weak auth it widens the attack surface immediately on apply.",
        verify:["Confirm public exposure is intended for this resource.","Check that authentication, WAF, and least-privilege security groups are in place.","Scope CIDR ranges to known clients instead of 0.0.0.0/0 where possible."],
        rollback:["Revert the scheme/ingress change to restore private access.","Rotate anything that may have been exposed during the window."]
      });
    }
  }

  if(/^aws_iam_/.test(type) && action!=="destroy"){
    fragments.push({
      severity:"medium",
      trigger:`IAM resource (${type}) is changing (${action}).`,
      impact:"Permission or trust changes can silently over-grant access or break a workload that relied on the old policy.",
      verify:["Diff the effective permissions and trust relationships against the previous policy.","Confirm the change follows least privilege; test the workload with the new policy in a non-production account if possible."],
      rollback:["Re-apply the previous policy document from source control \u2014 IAM changes take effect quickly in both directions."]
    });
  }

  if(/^aws_(security_group|route|vpc|subnet|network_acl)/.test(type) && !becamePublic(before,after).length){
    fragments.push({
      severity:"medium",
      trigger:`Network resource (${type}) is changing (${action}).`,
      impact:"Traffic paths between services can change, causing connectivity failures that only surface at runtime.",
      verify:["Trace which services rely on the affected routes / rules.","Test connectivity from dependent services after apply."],
      rollback:["Restore the previous network configuration and re-test paths."]
    });
  }

  return fragments;
}

// --- Dependency map ---------------------------------------------------------
// Derived only from configuration references present in the supplied plan.
// Anything the plan does not state is explicitly reported as unknown.
function buildDependencies(plan, resources){
  const changed=new Set(resources.map(r=>r.address));
  const edges=[];
  function walk(mod){
    (mod?.resources||[]).forEach(res=>{
      const from=res.address;
      const refs=new Set();
      (function collect(expr){
        if(!expr || typeof expr!=="object") return;
        if(Array.isArray(expr)){ expr.forEach(collect); return; }
        if(Array.isArray(expr.references)) expr.references.forEach(ref=>{
          const target=ref.split(".").slice(0,2).join(".");
          if(target && target!==from) refs.add(target);
        });
        Object.values(expr).forEach(collect);
      })(res.expressions);
      refs.forEach(to=>edges.push({from,to}));
    });
    // Module internals are out of scope for this view; anything inside
    // module calls is reported as unknown rather than guessed.
  }
  walk(plan.configuration?.root_module);
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

function analyze(plan){
  if(!plan || !Array.isArray(plan.resource_changes)) throw new Error("This is not a Terraform JSON plan with resource_changes. Run terraform show -json tfplan > plan.json.");
  if(plan.resource_changes.length>10000) throw new Error("This plan is too large for the browser review (10,000 resource changes maximum).");
  const resources=plan.resource_changes
    .map(item=>({address:String(item.address||"Unknown resource"),type:String(item.type||""),action:actionOf(item.change?.actions),before:item.change?.before,after:item.change?.after}))
    .filter(item=>item.action!=="no-op");

  const cards=[];
  resources.forEach(r=>{
    const fragments=evaluate(r);
    if(!fragments.length) return;
    const severity=fragments.reduce((s,f)=>SEV[f.severity]>SEV[s]?f.severity:s,"low");
    cards.push({
      address:r.address, type:r.type, action:r.action, severity,
      triggers:fragments.map(f=>f.trigger),
      impacts:[...new Set(fragments.map(f=>f.impact))],
      verify:[...new Set(fragments.flatMap(f=>f.verify))],
      rollback:[...new Set(fragments.flatMap(f=>f.rollback))]
    });
  });
  cards.sort((x,y)=>SEV[y.severity]-SEV[x.severity]);

  const questions=[...new Set(cards.flatMap(c=>c.verify).slice(0,3)),monitoringQuestion,ownerQuestion].slice(0,5);
  const dependencies=buildDependencies(plan, resources);
  return {resources,cards,questions,dependencies};
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
  lines.push(`## Summary`,``,`| Changing | Create | Update | Destroy/Replace |`,`|---|---|---|---|`,`| ${report.resources.length} | ${counts.create} | ${counts.update} | ${counts.destroy+counts.replace} |`,``);
  lines.push(`## Findings (${report.cards.length})`,``);
  if(!report.cards.length) lines.push(`No priority risk pattern detected. This does not prove the change is safe; review the full diff.`,``);
  report.cards.forEach(c=>{
    lines.push(`### ${c.severity.toUpperCase()} \u2014 \`${c.address}\` (${c.action})`,``);
    lines.push(`**Evidence:**`);
    c.triggers.forEach(t=>lines.push(`- ${t}`));
    lines.push(``,`**Likely impact:**`);
    c.impacts.forEach(t=>lines.push(`- ${t}`));
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
    node("p",null,highest==="high"?`${highCount} resource${highCount===1?"":"s"} could cause downtime, data loss, or exposure. Pause for a focused review before apply.`:highest==="medium"?"Some changes need a closer look before apply.":"No priority patterns detected. Still review the full diff before applying.")
  );
  verdict.append(copy);

  $("risk-count").textContent=report.cards.length?`${report.cards.length} flagged`:"none flagged";
  if(report.cards.length){
    $("risk-cards").replaceChildren(...report.cards.map(riskCard));
  }else{
    const ok=node("div","risk-empty");
    ok.append(node("strong",null,"No priority risk pattern detected"),node("p",null,"This plan shows no destructive, exposure, or data-loss patterns. Confirm intent and validate service-specific behavior before applying."));
    $("risk-cards").replaceChildren(ok);
  }

  renderDependencies(report.dependencies);
  renderComparison(currentComparison,name);

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
