#!/usr/bin/env python3
"""
GCP Security Posture & SOC Alignment Assessment Engine
Audits an entire GCP Organization or Project for CIS/SOC 2 compliance and generates an executive report.
"""

import os
import sys
import argparse
import subprocess
from datetime import datetime
from google.cloud import asset_v1
from google.cloud import securitycenter_v2
from google.protobuf.json_format import MessageToDict


def get_gcloud_default(command: list) -> str:
    """Attempts to auto-detect GCP settings from the local gcloud context."""
    try:
        result = subprocess.run(
            ["gcloud"] + command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except Exception:
        return ""


def parse_args():
    detected_proj = get_gcloud_default(["config", "get-value", "project"])
    detected_org = get_gcloud_default(["organizations", "list", "--format=value(ID)", "--limit=1"])

    parser = argparse.ArgumentParser(
        description="GCP Security Posture & SOC Alignment Audit Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--org-id",
        default=detected_org or os.environ.get("GCP_ORG_ID"),
        help="GCP Organization ID (Required for organization-wide scans)"
    )
    parser.add_argument(
        "--project-id",
        default=detected_proj or os.environ.get("GCP_PROJECT_ID"),
        help="GCP Project ID used for billing/quota routing"
    )
    parser.add_argument(
        "--client-name",
        default=os.environ.get("CLIENT_NAME", "Target Enterprise"),
        help="Customer or Partner Organization Name"
    )
    parser.add_argument(
        "--assessor-name",
        default=os.environ.get("ASSESSOR_NAME", "Cloud Security Assessment Practice"),
        help="Name of the assessment partner/auditor"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to save the generated HTML report"
    )

    args = parser.parse_args()

    if not args.org_id:
        print("[!] Error: No Organization ID detected.")
        print("    Specify --org-id <ID> or ensure 'gcloud organizations list' returns your Org ID.")
        sys.exit(1)

    if not args.project_id:
        print("[!] Error: No Project ID detected.")
        print("    Specify --project-id <ID> or set an active project with 'gcloud config set project <ID>'.")
        sys.exit(1)

    return args


def proto_to_dict(proto_obj):
    if not proto_obj:
        return {}
    if isinstance(proto_obj, dict):
        return proto_obj
    try:
        raw = getattr(proto_obj, "_pb", proto_obj)
        return MessageToDict(raw)
    except Exception:
        try:
            return dict(proto_obj)
        except Exception:
            return {}


class GCPSecurityAuditor:
    def __init__(self, org_id: str, project_id: str, client_name: str, assessor_name: str, output_dir: str):
        self.org_id = str(org_id)
        self.project_id = str(project_id)
        self.client_name = client_name
        self.assessor_name = assessor_name
        self.output_dir = output_dir
        self.scope = f"organizations/{self.org_id}"
        self.findings = []
        self.passed = 0
        self.failed = 0

        # Initialize Asset Client
        self.asset_client = asset_v1.AssetServiceClient()

    def add_result(self, section: str, control: str, plain_meaning: str, status: str, severity: str, details: list, remediation: str):
        if status == "PASS":
            self.passed += 1
        else:
            self.failed += 1
        self.findings.append({
            "section": section,
            "control": control,
            "plain_meaning": plain_meaning,
            "status": status,
            "severity": severity,
            "details": details,
            "remediation": remediation
        })

    def audit_iam(self):
        """Audits organization-wide IAM policies for standing primitive Owner/Editor roles."""
        print("[+] [1/4] Auditing Identity & Access Governance (IAM)...")
        primitive_roles = ["roles/owner", "roles/editor"]
        offenders = []

        try:
            policies = self.asset_client.search_all_iam_policies(
                request={
                    "scope": self.scope,
                    "query": 'policy: "roles/owner" OR policy: "roles/editor"'
                }
            )
            for item in policies:
                proj_name = item.project.split('/')[-1] if item.project else item.resource
                for binding in item.policy.bindings:
                    if binding.role in primitive_roles:
                        for member in binding.members:
                            offenders.append(f"{member} [{binding.role}] in project {proj_name}")

            if offenders:
                self.add_result(
                    section="Identity & Access Management",
                    control="Principle of Least Privilege (POLP)",
                    plain_meaning="Ensuring administrative master keys are restricted so accounts cannot delete systems or leak data.",
                    status="FAIL",
                    severity="CRITICAL",
                    details=offenders,
                    remediation="Strip primitive roles (roles/owner, roles/editor). Reassign identities to targeted predefined roles or GCP Privileged Access Manager (PAM)."
                )
            else:
                self.add_result(
                    section="Identity & Access Management",
                    control="Principle of Least Privilege (POLP)",
                    plain_meaning="Ensuring administrative master keys are restricted so accounts cannot delete systems or leak data.",
                    status="PASS",
                    severity="LOW",
                    details=["No standing primitive Owner/Editor roles found across the organization."],
                    remediation="Maintain existing least-privilege role policies."
                )
        except Exception as e:
            self.add_result(
                section="Identity & Access Management",
                control="Principle of Least Privilege (POLP)",
                plain_meaning="Access policy inspection.",
                status="FAIL",
                severity="HIGH",
                details=[f"API Scan Error: {str(e)[:140]}"],
                remediation="Ensure roles/cloudasset.viewer is granted at the organization level."
            )

    def audit_firewalls(self):
        """Audits firewalls across all VPCs for open database and host management ingress ports."""
        print("[+] [2/4] Auditing VPC Network Perimeter...")
        flagged_rules = []
        target_ports = {
            "3306": "MySQL/Database",
            "5432": "PostgreSQL",
            "1433": "MS SQL",
            "22": "SSH Host Management",
            "3389": "RDP Remote Desktop",
            "8080": "Application Port"
        }

        try:
            firewalls = self.asset_client.search_all_resources(
                request={
                    "scope": self.scope,
                    "asset_types": ["compute.googleapis.com/Firewall"],
                }
            )
            for fw in firewalls:
                resource_data = proto_to_dict(getattr(fw, "additional_attributes", None))
                source_ranges = resource_data.get("sourceRanges", [])
                allowed = resource_data.get("allowed", [])
                disabled = resource_data.get("disabled", False)

                if "0.0.0.0/0" in source_ranges and not disabled:
                    for rule in allowed:
                        ports = rule.get("ports", [])
                        for p in ports:
                            if p in target_ports:
                                flagged_rules.append(
                                    f"Rule: {fw.display_name} -> Port {p} [{target_ports[p]}] in project {fw.project.split('/')[-1]}"
                                )

            if flagged_rules:
                self.add_result(
                    section="Network Perimeter Security",
                    control="Restricted Public Access (Firewalls)",
                    plain_meaning="Checking that database and server management ports are not exposed to automated internet attackers.",
                    status="FAIL",
                    severity="CRITICAL",
                    details=flagged_rules,
                    remediation="Restrict ingress on management/DB ports to authorized IP CIDRs, or deploy Identity-Aware Proxy (IAP) TCP forwarding."
                )
            else:
                self.add_result(
                    section="Network Perimeter Security",
                    control="Restricted Public Access (Firewalls)",
                    plain_meaning="Checking that database and server management ports are not exposed to automated internet attackers.",
                    status="PASS",
                    severity="LOW",
                    details=["No open management or database ports (22, 3389, 3306, 5432, 1433, 8080) are open to 0.0.0.0/0."],
                    remediation="Maintain existing zero-trust firewall perimeters."
                )
        except Exception as e:
            self.add_result(
                section="Network Perimeter Security",
                control="Restricted Public Access (Firewalls)",
                plain_meaning="VPC Firewall evaluation.",
                status="FAIL",
                severity="HIGH",
                details=[f"API Scan Error: {str(e)[:140]}"],
                remediation="Verify Cloud Asset Viewer permissions on the organization."
            )

    def audit_storage_and_databases(self):
        """Audits Cloud Storage Public Access Prevention and Cloud SQL Public IP routing."""
        print("[+] [3/4] Auditing Cloud Storage & Database Isolation...")
        sql_issues = []
        bucket_issues = []

        try:
            # 1. Cloud SQL checks
            sql_instances = self.asset_client.search_all_resources(
                request={
                    "scope": self.scope,
                    "asset_types": ["sqladmin.googleapis.com/Instance"]
                }
            )
            for sql in sql_instances:
                attrs = proto_to_dict(getattr(sql, "additional_attributes", None))
                for ip in attrs.get("ipAddresses", []):
                    if ip.get("type") == "PRIMARY":
                        sql_issues.append(f"SQL Instance {sql.display_name} has a Public IP assigned in project {sql.project.split('/')[-1]}")

            if sql_issues:
                self.add_result(
                    section="Database Security",
                    control="Cloud SQL Private Network Routing",
                    plain_meaning="Confirming production databases are hidden behind private VPC subnets rather than public internet IPs.",
                    status="FAIL",
                    severity="HIGH",
                    details=sql_issues,
                    remediation="Disable Public IP addresses on Cloud SQL and enforce Private Services Access (PSA) or Private Service Connect (PSC)."
                )
            else:
                self.add_result(
                    section="Database Security",
                    control="Cloud SQL Private Network Routing",
                    plain_meaning="Confirming production databases are hidden behind private VPC subnets rather than public internet IPs.",
                    status="PASS",
                    severity="LOW",
                    details=["All Cloud SQL database instances enforce private network routing."],
                    remediation="Continue enforcing private VPC connectivity."
                )

            # 2. Storage Buckets checks
            buckets = self.asset_client.search_all_resources(
                request={
                    "scope": self.scope,
                    "asset_types": ["storage.googleapis.com/Bucket"]
                }
            )
            for b in buckets:
                attrs = proto_to_dict(getattr(b, "additional_attributes", None))
                pap = (
                    attrs.get("publicAccessPrevention") or
                    attrs.get("public_access_prevention") or
                    attrs.get("iamConfiguration", {}).get("publicAccessPrevention")
                )
                if pap != "enforced":
                    bucket_issues.append(f"Bucket {b.display_name} does not enforce Public Access Prevention (PAP)")

            if bucket_issues:
                self.add_result(
                    section="Data Storage Governance",
                    control="Public Access Prevention (PAP)",
                    plain_meaning="Ensuring document and file storage buckets cannot be accidentally configured for public internet download.",
                    status="FAIL",
                    severity="MEDIUM",
                    details=bucket_issues,
                    remediation="Enforce Public Access Prevention (PAP) and Uniform Bucket-Level Access (UBLA) across all storage buckets."
                )
            else:
                self.add_result(
                    section="Data Storage Governance",
                    control="Public Access Prevention (PAP)",
                    plain_meaning="Ensuring document and file storage buckets cannot be accidentally configured for public internet download.",
                    status="PASS",
                    severity="LOW",
                    details=["Public Access Prevention is active and enforced across all Cloud Storage buckets."],
                    remediation="Maintain storage organization policy constraints."
                )
        except Exception as e:
            self.add_result("Data Storage Governance", "Storage Audit", "Storage inspection.", "FAIL", "HIGH", [f"Error: {e}"], "N/A")

    def audit_security_command_center(self):
        """Audits Security Command Center (V2 API) for active High/Critical alerts."""
        print("[+] [4/4] Auditing Centralized SIEM & Threat Monitoring...")
        try:
            import google.auth
            credentials, _ = google.auth.default()
            if hasattr(credentials, "with_quota_project"):
                credentials = credentials.with_quota_project(self.project_id)

            scc_client = securitycenter_v2.SecurityCenterClient(credentials=credentials)
            v2_parent = f"organizations/{self.org_id}/sources/-/locations/global"

            req = securitycenter_v2.ListFindingsRequest(
                parent=v2_parent,
                filter='state="ACTIVE" AND (severity="CRITICAL" OR severity="HIGH")',
                page_size=20
            )

            active_threats = []
            for resp in scc_client.list_findings(request=req):
                finding = resp.finding
                active_threats.append(f"[{finding.severity.name}] {finding.category} on {finding.resource_name.split('/')[-1]}")

            if active_threats:
                self.add_result(
                    section="Threat Monitoring & Incident Readiness",
                    control="Security Command Center Active Findings",
                    plain_meaning="Detecting live, real-time intrusion indicators, compromised credentials, or critical vulnerabilities.",
                    status="FAIL",
                    severity="HIGH",
                    details=active_threats,
                    remediation="Remediate open High/Critical findings in the SCC Console and establish automated log routing to a SIEM."
                )
            else:
                self.add_result(
                    section="Threat Monitoring & Incident Readiness",
                    control="Security Command Center Active Findings",
                    plain_meaning="Detecting live, real-time intrusion indicators, compromised credentials, or critical vulnerabilities.",
                    status="PASS",
                    severity="LOW",
                    details=["Zero active CRITICAL or HIGH security findings detected across the environment."],
                    remediation="Maintain continuous 24/7 Security Command Center monitoring."
                )
        except Exception as e:
            err = str(e)
            if "Legacy has been permanently disabled" in err or "400" in err:
                details = ["SCC is not fully onboarded for this Organization."]
            else:
                details = [f"SCC Connection Notice: {err[:140]}"]
            self.add_result(
                section="Threat Monitoring & Incident Readiness",
                control="Security Command Center Central Visibility",
                plain_meaning="Continuous 24/7 posture and threat detection.",
                status="FAIL",
                severity="HIGH",
                details=details,
                remediation="Activate Security Command Center Standard (free) or Enterprise at the organization level."
            )

    def write_html_report(self):
        total = self.passed + self.failed
        score = (self.passed / total) * 100 if total > 0 else 0
        date_str = datetime.now().strftime("%B %d, %Y")
        clean_org = self.org_id.replace("/", "_")
        filename = os.path.join(self.output_dir, f"GCP_Security_Assessment_{clean_org}.html")

        failed_items = [f for f in self.findings if f["status"] != "PASS"]

        table_rows = ""
        for f in self.findings:
            badge = "badge-pass" if f["status"] == "PASS" else "badge-fail"
            table_rows += f"""
            <tr>
              <td><strong>{f['section']}</strong><br><small style="color:#5f6368;">{f['control']}</small></td>
              <td>{f['plain_meaning']}</td>
              <td><span class="{badge}">{f['status']}</span></td>
              <td><strong>{f['severity']}</strong></td>
            </tr>
            """

        remediation_cards = ""
        if failed_items:
            for idx, item in enumerate(failed_items, 1):
                details_list = "".join([f"<li><code>{d}</code></li>" for d in item['details'][:6]])
                if len(item['details']) > 6:
                    details_list += f"<li><em>...and {len(item['details']) - 6} additional instances.</em></li>"
                remediation_cards += f"""
                <div class="card">
                  <div class="card-header">
                    <span class="badge-priority">Priority 0{idx}</span>
                    <h3 style="margin:0; display:inline-block; margin-left: 10px;">{item['section']}: {item['control']}</h3>
                  </div>
                  <p><strong>Identified Exposure:</strong></p>
                  <ul>{details_list}</ul>
                  <p><strong>Business Impact:</strong> {item['plain_meaning']}</p>
                  <p><strong>Remediation Standard:</strong> {item['remediation']}</p>
                </div>
                """
        else:
            remediation_cards = """
            <div class="card" style="border-left: 5px solid #1e8e3e; background: #f6fbf7;">
              <h3 style="color: #0d652d; margin-top:0;">Clean Security Posture</h3>
              <p>All core Google Cloud Architecture Framework security controls evaluated during this scan are passing.</p>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GCP Security Posture Assessment - {self.client_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #202124; margin: 40px; background: #fff; }}
  .header {{ border-bottom: 3px solid #1a73e8; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-end; }}
  h1 {{ color: #1a73e8; margin: 0 0 8px 0; font-size: 26px; }}
  .meta {{ color: #5f6368; font-size: 14px; }}
  .scorecard {{ display: flex; gap: 20px; margin: 30px 0; }}
  .score-box {{ flex: 1; border: 1px solid #dadce0; border-radius: 8px; padding: 20px; text-align: center; }}
  .score-box.main {{ border-top: 6px solid {'#1e8e3e' if score >= 80 else '#d93025'}; background: {'#e6f4ea' if score >= 80 else '#fce8e6'}; }}
  .score-number {{ font-size: 42px; font-weight: 800; color: {'#1e8e3e' if score >= 80 else '#d93025'}; margin: 5px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 25px 0; }}
  th, td {{ border: 1px solid #dadce0; padding: 12px 14px; text-align: left; font-size: 14px; vertical-align: top; }}
  th {{ background-color: #f8f9fa; color: #202124; font-weight: 600; }}
  .badge-pass {{ background: #ceead6; color: #0d652d; padding: 4px 10px; border-radius: 12px; font-weight: bold; font-size: 12px; display: inline-block; }}
  .badge-fail {{ background: #fad2cf; color: #a50e0e; padding: 4px 10px; border-radius: 12px; font-weight: bold; font-size: 12px; display: inline-block; }}
  .badge-priority {{ background: #1a73e8; color: #fff; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; }}
  .card {{ border: 1px solid #dadce0; border-radius: 8px; padding: 20px; margin-bottom: 20px; page-break-inside: avoid; }}
  .card-header {{ margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
  .footer {{ margin-top: 50px; border-top: 1px solid #dadce0; padding-top: 20px; font-size: 12px; color: #70757a; display: flex; justify-content: space-between; }}
  @media print {{ body {{ margin: 10mm; }} }}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>Google Cloud Security & Controls Alignment Audit</h1>
    <div class="meta">
      <strong>Target Client:</strong> {self.client_name} &nbsp;|&nbsp;
      <strong>Organization ID:</strong> {self.org_id} &nbsp;|&nbsp;
      <strong>Date:</strong> {date_str}
    </div>
  </div>
  <div style="text-align: right; color: #1a73e8; font-weight: bold; font-size: 18px;">
    {self.assessor_name}
  </div>
</div>

<div class="scorecard">
  <div class="score-box main">
    <div style="font-size: 13px; font-weight: 600; text-transform: uppercase;">Overall Security Score</div>
    <div class="score-number">{score:.1f}%</div>
    <div><strong>{self.passed}</strong> of <strong>{total}</strong> Core Controls Passed</div>
  </div>
  <div class="score-box">
    <div style="font-size: 13px; font-weight: 600; text-transform: uppercase;">Actionable Gaps</div>
    <div class="score-number" style="color: {'#1e8e3e' if self.failed == 0 else '#d93025'};">{self.failed}</div>
    <div>Identified Exposure Areas</div>
  </div>
</div>

<h2>Executive Summary & Control Overview</h2>
<table>
  <thead>
    <tr>
      <th style="width: 25%;">Control Domain</th>
      <th style="width: 45%;">Plain-English Business Meaning</th>
      <th style="width: 15%;">Status</th>
      <th style="width: 15%;">Severity</th>
    </tr>
  </thead>
  <tbody>{table_rows}</tbody>
</table>

<h2>Prioritized Remediation Roadmap</h2>
{remediation_cards}

<div class="footer">
  <div>{self.assessor_name} &bull; Confidential Security Deliverable</div>
  <div>Generated for Organization ID {self.org_id}</div>
</div>

</body>
</html>
"""
        with open(filename, "w") as f:
            f.write(html)

        print("\n" + "=" * 80)
        print(f"AUDIT COMPLETE: {score:.1f}% ({self.passed}/{total} Controls Passed)")
        print(f"[✓] Executive PDF-Ready Report Saved: {filename}")
        print("=" * 80)

    def execute(self):
        print(f"\nTarget Client: {self.client_name}")
        print(f"Scope: {self.scope}")
        print(f"Billing/Quota Context: {self.project_id}\n")
        self.audit_iam()
        self.audit_firewalls()
        self.audit_storage_and_databases()
        self.audit_security_command_center()
        self.write_html_report()


if __name__ == "__main__":
    args = parse_args()
    auditor = GCPSecurityAuditor(
        org_id=args.org_id,
        project_id=args.project_id,
        client_name=args.client_name,
        assessor_name=args.assessor_name,
        output_dir=args.output_dir
    )
    auditor.execute()