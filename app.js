"use strict";
// All plan processing stays in the browser. Never render raw plan values or sensitive fields.
const $ = id => document.getElementById(id);

// --- Demo plans -------------------------------------------------------------
// Two realistic before/after stories so reviewers see the depth of judgment.
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
      ]
    }
  },
  risky: {
    label: "Sample: order service change (database + exposure)",
    plan: {
      format_version: "1.2",
      resource_changes: [
        {address:"aws_db_instance.orders",type:"aws_db_instance",change:{actions:["delete","create"],before:{deletion_protection:true,skip_final_snapshot:false,instance_class:"db.r6g.large"},after:{deletion_protection:false,skip_final_snapshot:true,instance_class:"db.r6g.xlarge"}}},
        {address:"aws_security_group.api",type:"aws_security_group",change:{actions:["update"],before:{ingress:[]},after:{ingress:[{cidr_blocks:["0.0.0.0/0"],from_port:443,to_port:443}]}}},
        {address:"aws_lb.public_api",type:"aws_lb",change:{actions:["update"],before:{internal:true},after:{internal:false}}},
        {address:"aws_iam_role_policy.api_access",type:"aws_iam_role_policy",change:{actions:["update"],before:{},after:{}}},
        {address:"aws_s3_bucket.legacy_logs",type:"aws_s3_bucket",change:{actions:["delete"],before:{bucket:"orders-legacy-logs"},after:null}},
        {address:"aws_cloudwatch_metric_alarm.api_5xx",type:"aws_cloudwatch_metric_alarm",change:{actions:["create"],before:null,after:{alarm_name:"api-5xx"}}}
      ]
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
const STATEFUL = /^(aws_db_|aws_rds_|aws_dynamodb_|aws_s3_bucket|aws_ebs_|aws_elasticache_|aws_efs_|aws_redshift_)/;
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

// --- Risk rules -------------------------------------------------------------
// Each rule inspects one resource and may return a risk fragment with the
// exact trigger, likely impact, and a verify + rollback checklist.
const SEV = {high:3, medium:2, low:1};

function evaluate(resource){
  const {type, action, before, after} = resource;
  const fragments=[];

  if(action==="replace"){
    fragments.push({
      severity:"high",
      trigger:"Action is replace \u2014 Terraform plans to recreate this resource. Unless create_before_destroy is set, the existing resource is destroyed before its replacement exists.",
      impact:"Depending on the resource and lifecycle configuration, expect possible downtime and loss of any state the resource holds. Dependents referencing its ID, ARN, or endpoint may break until the new resource is live.",
      verify:["Identify every resource and app config that references this resource's ID/ARN/endpoint.","Confirm a current backup or snapshot exists before apply.","Schedule a maintenance window if downtime is user-visible."],
      rollback:["Restore the resource from the latest snapshot/backup.","Re-point dependents to the restored identifier.","Revert the Terraform change and re-apply the previous state."]
    });
  } else if(action==="destroy"){
    fragments.push({
      severity:"high",
      trigger:"Action is destroy \u2014 this resource is removed with no replacement.",
      impact:"Anything depending on this resource loses it once applied. If it stores data, recovery depends on whatever backups exist outside this plan.",
      verify:["Confirm nothing in production still depends on this resource.","Export or snapshot any data you may need later."],
      rollback:["Recreate the resource from source control or a backup.","Note that some resources (buckets, DBs) cannot be restored to the same name/data instantly."]
    });
  }

  if(isStateful(type) && (action==="replace"||action==="destroy")){
    fragments.push({
      severity:"high",
      trigger:`Stateful resource (${type}) is planned for ${action==="replace"?"replacement":"destruction"}.`,
      impact:"Databases, storage, and caches hold data that recreation does not preserve. This is a data-loss risk, not just downtime.",
      verify:["Take a fresh manual snapshot immediately before apply.","Verify point-in-time recovery / final snapshot settings are enabled.","Dry-run the restore path so you know it works under pressure."],
      rollback:["Restore from the pre-apply snapshot.","Validate row counts / object counts against the last known-good state."]
    });
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
  if(a.skip_final_snapshot===true && b.skip_final_snapshot!==true && isStateful(type)){
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
      verify:["Diff the effective permissions and trust relationships.","Confirm the change follows least privilege."],
      rollback:["Re-apply the previous policy document from source control."]
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
      address:r.address,
      type:r.type,
      action:r.action,
      severity,
      triggers:fragments.map(f=>f.trigger),
      impacts:[...new Set(fragments.map(f=>f.impact))],
      verify:[...new Set(fragments.flatMap(f=>f.verify))],
      rollback:[...new Set(fragments.flatMap(f=>f.rollback))]
    });
  });
  cards.sort((x,y)=>SEV[y.severity]-SEV[x.severity]);

  const questions=[...new Set(cards.flatMap(c=>c.verify).slice(0,3)),monitoringQuestion,ownerQuestion].slice(0,5);
  return {resources,cards,questions};
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
  trig.append(node("h4",null,"What triggered this"));
  trig.append(list(card.triggers));
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

function render(plan,name){
  const report=analyze(plan),rs=report.resources,counts={create:0,update:0,destroy:0,replace:0};
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

  $("questions").replaceChildren(...report.questions.map(q=>node("li",null,q)));
  $("resource-list").replaceChildren(...rs.map(r=>{const el=node("div","resource");el.append(node("code",null,r.address),node("span",`action ${r.action}`,r.action.toUpperCase()));return el;}));

  $("empty").hidden=true;$("error").hidden=true;$("results").hidden=false;$("workspace").scrollIntoView({behavior:"smooth",block:"start"});
}

function fail(message){$("error").textContent=message;$("error").hidden=false;}

$("sample-safe").addEventListener("click",()=>render(samples.safe.plan,samples.safe.label));
$("sample-risky").addEventListener("click",()=>render(samples.risky.plan,samples.risky.label));
$("file").addEventListener("change",async event=>{
  const file=event.target.files?.[0];if(!file)return;
  if(file.size>10*1024*1024){fail("The file exceeds the 10 MB limit.");return;}
  try{render(JSON.parse(await file.text()),file.name);}
  catch(error){fail(error instanceof SyntaxError?"The selected file is not valid JSON.":error.message);}
  finally{event.target.value="";}
});
