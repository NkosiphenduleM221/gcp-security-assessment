# Google Cloud Platform (GCP) Security Posture & SOC Alignment Assessment

An automated, client-facing security auditing tool that scans an entire Google Cloud Organization against **Google Cloud Architecture Framework (Security Pillar)** and **SOC 2 Trust Services Criteria**.

It compiles live telemetry across IAM, VPC firewalls, Cloud Storage, Cloud SQL, and Security Command Center (V2), and outputs a co-branded, executive-ready HTML/PDF report with plain-English business risk translations.

---

## Prerequisites & Required Permissions

The Google Cloud identity (User or Service Account) executing the assessment requires read visibility at the **Organization level**:

| Role | Role ID | Purpose |
| :--- | :--- | :--- |
| **Cloud Asset Viewer** | `roles/cloudasset.viewer` | Scans IAM policies, firewalls, GCS buckets, and SQL instances organization-wide. |
| **Security Center Admin Viewer** | `roles/securitycenter.adminViewer` | Queries active Security Command Center (V2) findings and threat detection logs. |

### Granting Permissions
An Organization Administrator can grant these roles via Google Cloud Shell:

```bash
export ORG_ID="YOUR_ORGANIZATION_ID"
export USER_EMAIL="user@example.com"

gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="user:$USER_EMAIL" \
    --role="roles/cloudasset.viewer"

gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="user:$USER_EMAIL" \
    --role="roles/securitycenter.adminViewer"
    