terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  type        = string
  description = "The GCP Project ID where resources reside."
}

variable "organization_id" {
  type        = string
  description = "The GCP Organization ID for SCC and IAM posture checks."
}

variable "region" {
  type    = string
  default = "us-central1"
}

# 1. Enable Security, Asset, DLP, and AI Services
resource "google_project_service" "security_services" {
  for_each = toset([
    "securitycenter.googleapis.com",
    "dlp.googleapis.com",
    "cloudasset.googleapis.com",
    "accesscontextmanager.googleapis.com",
    "aiplatform.googleapis.com", # Vertex AI for Gemini Agent
    "bigquery.googleapis.com"
  ])
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# 2. BigQuery Dataset for Posture Analytics Export
resource "google_bigquery_dataset" "scc_export_dataset" {
  dataset_id                 = "gcp_security_posture_reports"
  friendly_name              = "GCP Security Posture Reports"
  description                = "Dataset storing SCC findings and DLP posture scans for Gemini AI analysis."
  location                   = "US"
  delete_contents_on_destroy = false

  depends_on = [google_project_service.security_services]
}

# 3. Continuous SCC BigQuery Export
resource "google_scc_organization_scc_big_query_export" "scc_export" {
  name         = "scc-posture-export"
  organization = var.organization_id
  dataset      = google_bigquery_dataset.scc_export_dataset.id
  description  = "Export active Security Health Analytics findings to BigQuery"
  filter       = "state=\"ACTIVE\""
}

# 4. Cloud DLP Inspection Template for Sensitive Tokens and PII
resource "google_data_loss_prevention_inspect_template" "dlp_template" {
  parent       = "projects/${var.project_id}"
  display_name = "Gemini Readiness DLP Template"
  description  = "Inspects GCP storage and assets for PII, credentials, and sensitive tokens."

  inspect_config {
    info_types { name = "EMAIL_ADDRESS" }
    info_types { name = "CREDIT_CARD_NUMBER" }
    info_types { name = "GCP_CREDENTIALS" }
    info_types { name = "JSON_WEB_TOKEN" }

    min_likelihood = "LIKELY"

    limits {
      max_findings_per_request = 100
    }
  }
}

# 5. Service Account for Gemini Security Readiness Agent
resource "google_service_account" "gemini_agent_sa" {
  account_id   = "gemini-security-agent-sa"
  display_name = "Gemini GCP Security Posture Agent SA"
}

# Grant Agent SA read access to SCC, Asset Inventory, and Vertex AI
resource "google_organization_iam_member" "scc_admin" {
  org_id = var.organization_id
  role   = "roles/securitycenter.adminViewer"
  member = "serviceAccount:${google_service_account.gemini_agent_sa.email}"
}

resource "google_organization_iam_member" "asset_viewer" {
  org_id = var.organization_id
  role   = "roles/cloudasset.viewer"
  member = "serviceAccount:${google_service_account.gemini_agent_sa.email}"
}

resource "google_project_iam_member" "vertex_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.gemini_agent_sa.email}"
}