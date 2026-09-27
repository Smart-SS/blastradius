const fs = require("fs");
const src = fs.readFileSync("app.js", "utf8");
function fakeEl(){return{_t:"",set textContent(v){this._t=v},get textContent(){return this._t},className:"",hidden:false,append(){},replaceChildren(){},scrollIntoView(){},addEventListener(){},click(){},href:"",download:""};}
global.document={getElementById:()=>fakeEl(),createElement:()=>fakeEl()};
global.URL={createObjectURL:()=>"blob:x",revokeObjectURL(){}};
global.Blob=class{constructor(a){this.parts=a;}};
const m={exports:{}};
new Function("module","document","URL","Blob",src+"\nmodule.exports={analyze,samples,toMarkdown};")(m,global.document,global.URL,global.Blob);
const {analyze,samples,toMarkdown}=m.exports;

const fixture={
  format_version:"1.2",
  resource_changes:[
    // 1) DB replacement + retention drop to 0 (destroy-before-create order)
    {address:"aws_db_instance.main",type:"aws_db_instance",change:{actions:["delete","create"],before:{deletion_protection:true,skip_final_snapshot:false,backup_retention_period:14},after:{deletion_protection:false,skip_final_snapshot:true,backup_retention_period:0}}},
    // 2) Standalone classic SG rule: 0.0.0.0/0 on postgres
    {address:"aws_security_group_rule.pg_world",type:"aws_security_group_rule",change:{actions:["create"],before:null,after:{type:"ingress",from_port:5432,to_port:5432,cidr_blocks:["0.0.0.0/0"]}}},
    // 3) Standalone modern SG rule: ::/0 on SSH
    {address:"aws_vpc_security_group_ingress_rule.ssh6",type:"aws_vpc_security_group_ingress_rule",change:{actions:["create"],before:null,after:{from_port:22,to_port:22,cidr_ipv6:"::/0"}}},
    // 4) Inline IPv6 ingress on a security group
    {address:"aws_security_group.app",type:"aws_security_group",change:{actions:["update"],before:{ingress:[]},after:{ingress:[{from_port:22,to_port:22,ipv6_cidr_blocks:["::/0"]}]}}},
    // 5) S3 public access block weakened
    {address:"aws_s3_bucket_public_access_block.site",type:"aws_s3_bucket_public_access_block",change:{actions:["update"],before:{block_public_acls:true,block_public_policy:true,ignore_public_acls:true,restrict_public_buckets:true},after:{block_public_acls:false,block_public_policy:false,ignore_public_acls:true,restrict_public_buckets:true}}},
    // 6) Anonymous-read bucket policy
    {address:"aws_s3_bucket_policy.site",type:"aws_s3_bucket_policy",change:{actions:["update"],before:{policy:'{"Version":"2012-10-17","Statement":[]}'},after:{policy:'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::site/*"}]}'}}},
    // 7) Lifecycle retention 365 -> 7 (array-shaped, as real plan JSON renders blocks)
    {address:"aws_s3_bucket_lifecycle_configuration.logs",type:"aws_s3_bucket_lifecycle_configuration",change:{actions:["update"],before:{rule:[{expiration:[{days:365}]}]},after:{rule:[{expiration:[{days:7}]}]}}},
    // 7b) Object-shaped lifecycle still works
    {address:"aws_s3_bucket_lifecycle_configuration.obj",type:"aws_s3_bucket_lifecycle_configuration",change:{actions:["update"],before:{rule:{expiration:{days:90}}},after:{rule:{expiration:{days:3}}}}},
    // 7c) Launch template replacement (create-before-destroy)
    {address:"aws_launch_template.app",type:"aws_launch_template",change:{actions:["create","delete"],before:{instance_type:"m5.large"},after:{instance_type:"m6.large"}}},
    // 8) IAM wildcard expansion
    {address:"aws_iam_role_policy.app",type:"aws_iam_role_policy",change:{actions:["update"],before:{policy:'{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::x/*"}]}'},after:{policy:'{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'}}},
    // 9) ECS scale to zero
    {address:"aws_ecs_service.api",type:"aws_ecs_service",change:{actions:["update"],before:{desired_count:4},after:{desired_count:0}}},
    // 10) Alarm actions disabled
    {address:"aws_cloudwatch_metric_alarm.errors",type:"aws_cloudwatch_metric_alarm",change:{actions:["update"],before:{actions_enabled:true},after:{actions_enabled:false}}},
    // 11) ElastiCache snapshot retention shortened
    {address:"aws_elasticache_replication_group.cache",type:"aws_elasticache_replication_group",change:{actions:["update"],before:{snapshot_retention_limit:7},after:{snapshot_retention_limit:1}}},
    // 12) Log group retention shortened
    {address:"aws_cloudwatch_log_group.app",type:"aws_cloudwatch_log_group",change:{actions:["update"],before:{retention_in_days:365},after:{retention_in_days:7}}},
    // 13) Tag-only SG update (should be suppressed)
    {address:"aws_security_group.tags_only",type:"aws_security_group",change:{actions:["update"],before:{ingress:[],tags:{env:"a"}},after:{ingress:[],tags:{env:"b"}}}},
    // 14) create-before-destroy replacement (LB)
    {address:"aws_lb.app",type:"aws_lb",change:{actions:["create","delete"],before:{internal:true},after:{internal:true}}},
    // 15) child module resource
    {address:"module.net.aws_security_group.inner",type:"aws_security_group",change:{actions:["update"],before:{ingress:[]},after:{ingress:[]}}},
    // 16) Encryption disabled
    {address:"aws_db_instance.enc",type:"aws_db_instance",change:{actions:["update"],before:{storage_encrypted:true},after:{storage_encrypted:false}}},
    // 17) Multi-AZ disabled
    {address:"aws_db_instance.ha",type:"aws_db_instance",change:{actions:["update"],before:{multi_az:true},after:{multi_az:false}}},
    // 18) CloudTrail logging disabled
    {address:"aws_cloudtrail.main",type:"aws_cloudtrail",change:{actions:["update"],before:{enable_logging:true},after:{enable_logging:false}}},
    // 19) NAT gateway destroyed
    {address:"aws_nat_gateway.a",type:"aws_nat_gateway",change:{actions:["delete"],before:{id:"nat-1"},after:null}},
    // 20) Flagged resource with an unknown watched field (after_unknown) and a sensitive one
    {address:"aws_db_instance.unknown",type:"aws_db_instance",change:{actions:["update"],before:{deletion_protection:true},after:{deletion_protection:false},after_unknown:{backup_retention_period:true},after_sensitive:{policy:true}}},
    // 21) Un-flagged resources with unknown non-watched fields (endpoint, environment)
    {address:"aws_db_instance.endpoint_unknown",type:"aws_db_instance",change:{actions:["update"],before:{instance_class:"db.t3.micro"},after:{instance_class:"db.t3.small"},after_unknown:{endpoint:true}}},
    {address:"aws_lambda_function.env",type:"aws_lambda_function",change:{actions:["update"],before:{memory_size:128},after:{memory_size:256},after_sensitive:{environment:[{variables:true}]}}}
  ],
  configuration:{root_module:{
    resources:[{address:"aws_ecs_service.api",expressions:{network_configuration:{references:["module.net.aws_security_group.inner.id","module.net.aws_security_group.inner"]}}}],
    module_calls:{net:{module:{resources:[{address:"aws_security_group.inner",expressions:{vpc_id:{references:["var.vpc_id"]}}}]}}}
  }}
};

const r=analyze(fixture);
const card=addr=>r.cards.find(c=>c.address===addr);
const T=(name,cond)=>console.log((cond?"PASS":"FAIL")+" - "+name);

T("DB: backup_retention_period 14->0 flagged high", /backup_retention_period reduced 14 \u2192 0/.test((card("aws_db_instance.main")||{triggers:[]}).triggers.join(" ")));
T("DB: destroy-before-create order stated", /destroys the existing resource before creating/.test(card("aws_db_instance.main").triggers.join(" ")));
T("Standalone classic rule: IPv4 postgres flagged", /0\.0\.0\.0\/0 \(IPv4\) on port 5432/.test((card("aws_security_group_rule.pg_world")||{triggers:[]}).triggers.join(" ")));
T("Standalone modern rule: IPv6 SSH flagged", /::\/0 \(IPv6\) on port 22/.test((card("aws_vpc_security_group_ingress_rule.ssh6")||{triggers:[]}).triggers.join(" ")));
T("Inline IPv6: cited as ::/0 (IPv6), not IPv4", /::\/0 \(IPv6\) on port 22/.test(card("aws_security_group.app").triggers.join(" ")) && !/0\.0\.0\.0/.test(card("aws_security_group.app").triggers.join(" ")));
T("S3 public access block weakening flagged", /block_public_acls true \u2192 false/.test((card("aws_s3_bucket_public_access_block.site")||{triggers:[]}).triggers.join(" ")));
T("Anonymous bucket policy flagged", /Principal "\*"/.test((card("aws_s3_bucket_policy.site")||{triggers:[]}).triggers.join(" ")));
T("Lifecycle 365->7 flagged (array-shaped)", /365 \u2192 7/.test((card("aws_s3_bucket_lifecycle_configuration.logs")||{triggers:[]}).triggers.join(" ")));
T("Lifecycle 90->3 flagged (object-shaped)", /90 \u2192 3/.test((card("aws_s3_bucket_lifecycle_configuration.obj")||{triggers:[]}).triggers.join(" ")));
T("Launch template: template-specific guidance (versions/ASG), no backup advice", (()=>{const c=card("aws_launch_template.app");if(!c)return false;const all=c.verify.join(" ")+c.rollback.join(" ")+c.impacts.join(" ");return /previous version/.test(all)&&/Auto Scaling/.test(all)&&!/snapshot or backup|PITR/.test(all);})());
T("Anonymous policy wording acknowledges other controls", /also depends on the bucket's public access block/.test((card("aws_s3_bucket_policy.site")||{impacts:[]}).impacts.join(" ")));
T("IAM wildcard wording acknowledges boundaries/SCPs", /permissions boundaries, SCPs/.test((card("aws_iam_role_policy.app")||{impacts:[]}).impacts.join(" ")));
T("Ingress wording: permissive rule, reachability not asserted", /Actual internet reachability also depends/.test((card("aws_security_group_rule.pg_world")||{impacts:[]}).impacts.join(" ")));
T("Log retention wording: investigation/audit history, not recovery", /investigation and audit history/.test((card("aws_cloudwatch_log_group.app")||{impacts:[]}).impacts.join(" ")) && !/recovery window/.test((card("aws_cloudwatch_log_group.app")||{impacts:[]}).impacts.join(" ")));
T("IAM wildcard Action*/Resource* flagged high", (card("aws_iam_role_policy.app")||{severity:""}).severity==="high" && /Action: "\*" on Resource: "\*"/.test(card("aws_iam_role_policy.app").triggers.join(" ")));
T("ECS desired_count->0 flagged high", /desired_count reduced 4 \u2192 0/.test((card("aws_ecs_service.api")||{triggers:[]}).triggers.join(" ")));
T("Alarm actions_enabled=false flagged", /actions_enabled changed to false/.test((card("aws_cloudwatch_metric_alarm.errors")||{triggers:[]}).triggers.join(" ")));
T("Cache snapshot retention 7->1 flagged", /snapshot_retention_limit reduced 7 \u2192 1/.test((card("aws_elasticache_replication_group.cache")||{triggers:[]}).triggers.join(" ")));
T("Log retention 365->7 flagged", /retention_in_days reduced 365 \u2192 7/.test((card("aws_cloudwatch_log_group.app")||{triggers:[]}).triggers.join(" ")));
T("Tag-only SG update suppressed", !card("aws_security_group.tags_only"));
T("LB create-before-destroy order stated", /creates the replacement before destroying/.test((card("aws_lb.app")||{triggers:[]}).triggers.join(" ")));
T("Honest wording: 'No exposure pattern was detected by the supported checks'", r.cards.some(c=>/No exposure pattern was detected by the supported checks/.test(c.triggers.join(" "))));
T("Child-module dependency edge found", r.dependencies.edges.some(e=>e.from==="aws_ecs_service.api"&&e.to==="module.net.aws_security_group.inner"));

// Tier 1+2 checks
T("Encryption disabled flagged high", (card("aws_db_instance.enc")||{severity:""}).severity==="high" && /storage_encrypted changed true \u2192 false/.test(card("aws_db_instance.enc").triggers.join(" ")));
T("Multi-AZ disabled flagged", /multi_az changed true \u2192 false/.test((card("aws_db_instance.ha")||{triggers:[]}).triggers.join(" ")));
T("CloudTrail logging disabled flagged high", (card("aws_cloudtrail.main")||{severity:""}).severity==="high");
T("NAT gateway destroy flagged", Boolean(card("aws_nat_gateway.a")));
T("after_unknown caveat surfaced on flagged card", /backup_retention_period is not known until apply/.test((card("aws_db_instance.unknown")||{caveats:[]}).caveats.join(" ")));
T("after_sensitive caveat surfaced on flagged card", /policy is masked as sensitive/.test((card("aws_db_instance.unknown")||{caveats:[]}).caveats.join(" ")));
T("Risk score present and positive", typeof r.score==="number" && r.score>0 && r.score<=10);
T("Coverage disclosure lists 12 checks", Array.isArray(r.checks) && r.checks.length===12);
const md=toMarkdown(r,"fixture.json",null,"");
T("Markdown includes risk score", /Risk score/.test(md));
T("Markdown includes 'Not evaluable from this plan'", /Not evaluable from this plan/.test(md));
T("Markdown includes coverage disclosure section", /## Coverage \u2014 what this review checked/.test(md) && r.checks.every(c=>md.includes(c)));
T("Plan-level unknowns include non-watched endpoint field", r.unknowns.some(u=>u.address==="aws_db_instance.endpoint_unknown"&&/endpoint is not known until apply/.test(u.caveats.join(" "))));
T("Plan-level unknowns include sensitive lambda environment", r.unknowns.some(u=>u.address==="aws_lambda_function.env"&&/environment is masked as sensitive/.test(u.caveats.join(" "))));
T("Markdown lists plan-level unknowns (endpoint, environment)", /aws_db_instance\.endpoint_unknown/.test(md) && /environment is masked as sensitive/.test(md));
T("Launch template: workload/data impact wording, no absolute 'No data is at risk'", (()=>{const c=card("aws_launch_template.app");if(!c)return false;const all=c.impacts.join(" ");return /Review potential workload and data impacts separately/.test(all)&&!/No data is at risk/.test(all);})());
T("Launch template rollback distinguishes version vs whole-template, no availability assumption", (()=>{const c=card("aws_launch_template.app");if(!c)return false;const rb=c.rollback.join(" ");return /If only a new version was created/.test(rb)&&/may no longer exist/.test(rb)&&!/versions are retained/.test(rb);})());
T("Launch template replace: no generic snapshot/backup rollback", !/backup\/snapshot|data comes back only from backups/.test((card("aws_launch_template.app")||{rollback:[]}).rollback.join(" ")));
T("Launch template: single consistent fragment (no generic replace trigger)", (()=>{const c=card("aws_launch_template.app");return c && !c.triggers.some(t=>/^Action is replace/.test(t)) && c.triggers.some(t=>/creates the replacement before destroying/.test(t));})());

// regression: shipped samples still behave
const risky=analyze(samples.risky.plan), safe=analyze(samples.safe.plan);
T("regression: safe sample has 0 cards", safe.cards.length===0);
T("regression: risky sample still flags DB", Boolean(risky.cards.find(c=>c.address==="aws_db_instance.orders")));
console.log("\ncards:", r.cards.length, "| dep edges:", r.dependencies.edges.length, "| unknown:", r.dependencies.unknown.length);
