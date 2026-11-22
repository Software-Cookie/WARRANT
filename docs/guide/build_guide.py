"""Builds Warrant_GCP_Deployment_Guide.pdf.  python build_guide.py <brand_dir> <shots_dir> <out.pdf>"""
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, Image, KeepTogether, NextPageTemplate,
                                PageBreak, PageTemplate, Paragraph, Preformatted, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

BRAND, SHOTS, OUT = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
FONTS = Path("C:/Windows/Fonts")
pdfmetrics.registerFont(TTFont("Sans", str(FONTS / "segoeui.ttf")))
pdfmetrics.registerFont(TTFont("Sans-Bold", str(FONTS / "segoeuib.ttf")))
pdfmetrics.registerFont(TTFont("Mono", str(FONTS / "consola.ttf")))
pdfmetrics.registerFont(TTFont("Mono-Bold", str(FONTS / "consolab.ttf")))
pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-Bold", italic="Sans", boldItalic="Sans-Bold")

INK = colors.HexColor("#181816")
MUTED = colors.HexColor("#52524E")
FAINT = colors.HexColor("#8A8A85")
LINE = colors.HexColor("#DEDDD8")
SUNKEN = colors.HexColor("#F2F2EF")
CODEBG = colors.HexColor("#1E1E1C")
DANGER = colors.HexColor("#8C2F23")
CAUTION = colors.HexColor("#7A5A14")
SAFE = colors.HexColor("#28543F")
DARK = colors.HexColor("#111110")

W, H = A4
MARGIN = 18 * mm
CONTENT_W = W - 2 * MARGIN

body = ParagraphStyle("body", fontName="Sans", fontSize=9.6, leading=14.2, textColor=INK, spaceAfter=5)
small = ParagraphStyle("small", parent=body, fontSize=8.4, leading=11.6, textColor=MUTED)
lead = ParagraphStyle("lead", parent=body, fontSize=11, leading=16, textColor=MUTED, spaceAfter=8)
h1 = ParagraphStyle("h1", fontName="Sans-Bold", fontSize=20, leading=25, textColor=INK, spaceBefore=4, spaceAfter=10)
h2 = ParagraphStyle("h2", fontName="Sans-Bold", fontSize=13, leading=17, textColor=INK, spaceBefore=12, spaceAfter=5)
h3 = ParagraphStyle("h3", fontName="Sans-Bold", fontSize=10.4, leading=14, textColor=INK, spaceBefore=8, spaceAfter=3)
bullet = ParagraphStyle("bullet", parent=body, leftIndent=12, bulletIndent=2, spaceAfter=2.5)
cell = ParagraphStyle("cell", parent=body, fontSize=8.4, leading=11.2, spaceAfter=0)
cellb = ParagraphStyle("cellb", parent=cell, fontName="Sans-Bold")
code_style = ParagraphStyle("code", fontName="Mono", fontSize=7.9, leading=10.6, textColor=colors.HexColor("#ECECE8"))
toc1 = ParagraphStyle("toc1", fontName="Sans", fontSize=10, leading=14.5, textColor=INK, leftIndent=0)
toc2 = ParagraphStyle("toc2", fontName="Sans", fontSize=8.4, leading=10.6, textColor=MUTED, leftIndent=14)

story = []


def c(text):
    """Inline code."""
    return f'<font name="Mono" size="8.6" color="#3A3A36">{escape(text)}</font>'


def p(text, style=body):
    story.append(Paragraph(text, style))


def heading(text, level=1):
    style = h1 if level == 1 else h2
    story.append(CondPageBreak(60 * mm if level == 1 else 38 * mm))
    para = Paragraph(text, style)
    para._toc_level = level - 1
    story.append(para)


def bullets(items, style=bullet):
    for item in items:
        story.append(Paragraph(item, style, bulletText="•"))
    story.append(Spacer(1, 3))


def numbered(items):
    for i, item in enumerate(items, start=1):
        story.append(Paragraph(item, bullet, bulletText=f"{i}."))
    story.append(Spacer(1, 3))


def code(text):
    pre = Preformatted(text.strip("\n"), code_style)
    t = Table([[pre]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODEBG),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))


def callout(kind, text):
    color = {"security": SAFE, "warning": DANGER, "note": CAUTION, "check": SAFE}[kind]
    label = {"security": "SECURITY", "warning": "IMPORTANT", "note": "NOTE", "check": "CHECK"}[kind]
    content = Paragraph(f'<font name="Sans-Bold" color="{color.hexval()}">{label}</font>  {text}', cell)
    t = Table([["", content]], colWidths=[3, CONTENT_W - 3])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), color), ("BACKGROUND", (1, 0), (1, 0), SUNKEN),
        ("LEFTPADDING", (1, 0), (1, 0), 9), ("RIGHTPADDING", (1, 0), (1, 0), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (0, 0), 0),
    ]))
    story.append(t)
    story.append(Spacer(1, 7))


def table(header, rows, widths):
    data = [[Paragraph(h, cellb) for h in header]] + [[Paragraph(str(v), cell) for v in r] for r in rows]
    total = sum(widths)
    t = Table(data, colWidths=[CONTENT_W * w / total for w in widths], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SUNKEN),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))


def step(number, title, goal):
    story.append(CondPageBreak(72 * mm))
    para = Paragraph(f'<font color="{FAINT.hexval()}">Step {number}</font>  {escape(title)}', h2)
    para._toc_level = 1
    story.append(para)
    p(goal, lead)


def screenshot(name, caption, width=CONTENT_W):
    path = SHOTS / name
    img = Image(str(path))
    ratio = img.imageHeight / img.imageWidth
    img.drawWidth, img.drawHeight = width, width * ratio
    max_h = 150 * mm
    if img.drawHeight > max_h:
        img.drawHeight, img.drawWidth = max_h, max_h / ratio
    frame = Table([[img]], colWidths=[img.drawWidth + 2])
    frame.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, LINE), ("LEFTPADDING", (0, 0), (-1, -1), 1),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 1), ("TOPPADDING", (0, 0), (-1, -1), 1),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
    story.append(KeepTogether([frame, Spacer(1, 3), Paragraph(caption, small), Spacer(1, 8)]))


# ------------------------------------------------------------------------------------------------ diagrams

def box(d, x, y, w, h, title, sub=None, fill=colors.white, stroke=INK, text=INK, bold=True):
    d.add(Rect(x, y, w, h, rx=4, ry=4, fillColor=fill, strokeColor=stroke, strokeWidth=0.8))
    d.add(String(x + w / 2, y + h / 2 + (3 if sub else -3), title, fontName="Sans-Bold" if bold else "Sans",
                 fontSize=7.6, fillColor=text, textAnchor="middle"))
    if sub:
        d.add(String(x + w / 2, y + h / 2 - 7.5, sub, fontName="Sans", fontSize=6.2, fillColor=MUTED if text == INK else text,
                     textAnchor="middle"))


def arrow(d, x1, y1, x2, y2, color=INK, label=None, dx=0, dy=3):
    d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=0.8))
    import math
    a = math.atan2(y2 - y1, x2 - x1)
    s = 4.5
    d.add(Polygon([x2, y2, x2 - s * math.cos(a - 0.4), y2 - s * math.sin(a - 0.4),
                   x2 - s * math.cos(a + 0.4), y2 - s * math.sin(a + 0.4)], fillColor=color, strokeColor=color))
    if label:
        d.add(String((x1 + x2) / 2 + dx, (y1 + y2) / 2 + dy, label, fontName="Sans", fontSize=6, fillColor=MUTED,
                     textAnchor="middle"))


def architecture():
    dw, dh = CONTENT_W, 300
    d = Drawing(dw, dh)
    d.add(Rect(108, 6, dw - 112, dh - 12, rx=8, ry=8, fillColor=colors.HexColor("#FAFAF8"), strokeColor=LINE,
               strokeWidth=1, strokeDashArray=[3, 2]))
    d.add(String(116, dh - 20, "Google Cloud project  ·  one region (default asia-south1)", fontName="Sans-Bold",
                 fontSize=7, fillColor=MUTED))
    d.add(Rect(192, 10, dw - 200, dh - 38, rx=6, ry=6, fillColor=None, strokeColor=colors.HexColor("#C9C8C2"),
               strokeWidth=0.7))
    d.add(String(200, dh - 40, "VPC  ·  Direct VPC egress  ·  private service access  ·  Cloud NAT", fontName="Sans",
                 fontSize=6.4, fillColor=MUTED))
    # outside the project
    box(d, 4, 212, 92, 30, "Approver / admin", "browser · Google sign-in")
    box(d, 4, 152, 92, 30, "AI agent", "your application")
    box(d, 4, 85, 92, 30, "Target systems", "ERP · databases · APIs")
    # edge
    box(d, 120, 144, 60, 106, "HTTPS LB", "Cloud Armor", fill=SUNKEN)
    d.add(String(150, 160, "console. api. pep.", fontName="Sans", fontSize=5.6, fillColor=MUTED, textAnchor="middle"))
    # services
    box(d, 204, 212, 92, 30, "console", "Cloud Run")
    box(d, 316, 212, 92, 30, "control-plane", "Cloud Run")
    box(d, 204, 152, 92, 30, "pep-gateway", "Cloud Run · min 2")
    box(d, 316, 152, 92, 30, "classifier", "Cloud Run · internal")
    box(d, 420, 152, 58, 30, "Gemma", "GKE · optional")
    box(d, 316, 96, 92, 30, "warrant-migrate", "Cloud Run job")
    # data
    d.add(Rect(204, 16, 274, 58, rx=5, ry=5, fillColor=SUNKEN, strokeColor=LINE, strokeWidth=0.6))
    d.add(String(212, 64, "Private access only", fontName="Sans-Bold", fontSize=6.4, fillColor=MUTED))
    for i, (t, sub) in enumerate([("Cloud SQL", "PG16 · IAM auth"), ("Memorystore", "Redis 7.2 · TLS"),
                                  ("Cloud KMS", "HSM · Ed25519"), ("Secret Manager", "credentials")]):
        box(d, 210 + i * 67, 22, 62, 34, t, sub)
    # flows
    arrow(d, 96, 227, 120, 227)
    arrow(d, 96, 167, 120, 167)
    arrow(d, 180, 227, 204, 227)
    arrow(d, 180, 167, 204, 167)
    arrow(d, 296, 227, 316, 227)
    arrow(d, 296, 167, 316, 167)
    arrow(d, 408, 167, 420, 167)
    arrow(d, 284, 182, 328, 212)
    d.add(String(318, 194, "ID token", fontName="Sans", fontSize=5.8, fillColor=MUTED))
    d.add(Line(216, 152, 216, 100, strokeColor=SAFE, strokeWidth=0.9))
    arrow(d, 216, 100, 96, 100, color=SAFE)
    d.add(String(156, 104, "credential injected, forwarded", fontName="Sans", fontSize=5.8, fillColor=SAFE,
                 textAnchor="middle"))
    arrow(d, 262, 152, 262, 74)
    arrow(d, 362, 96, 362, 74)
    d.add(Line(408, 227, 482, 227, strokeColor=INK, strokeWidth=0.8))
    d.add(Line(482, 227, 482, 45, strokeColor=INK, strokeWidth=0.8))
    arrow(d, 482, 45, 478, 45)
    return d


def pipeline():
    dw, dh = CONTENT_W, 40 * mm
    d = Drawing(dw, dh)
    stages = [("Verify", "warrant · proof"), ("Derive verb", "from the call"), ("L0 cache", "same call + policy"),
              ("L1 policy", "scope · ceilings"), ("L2 model", "blast radius · drift"), ("Combine", "stricter only")]
    w = (dw - 5 * 8) / 6
    for i, (title, sub) in enumerate(stages):
        x = i * (w + 8)
        box(d, x, dh - 44, w, 34, title, None, fill=SUNKEN)
        d.add(String(x + w / 2, dh - 56, sub, fontName="Sans", fontSize=5.8, fillColor=MUTED, textAnchor="middle"))
        if i < 5:
            arrow(d, x + w, dh - 27, x + w + 8, dh - 27)
    outs = [("ALLOW", "credential injected, forwarded", colors.HexColor("#4A4A46")),
            ("ESCALATE", "parked; card to a human; timeout = deny", CAUTION),
            ("DENY", "reason code from a closed set", DANGER)]
    ow = (dw - 2 * 10) / 3
    for i, (title, sub, color) in enumerate(outs):
        x = i * (ow + 10)
        d.add(Rect(x, 4, ow, 26, rx=4, ry=4, fillColor=color, strokeColor=color))
        d.add(String(x + ow / 2, 19, title, fontName="Sans-Bold", fontSize=8, fillColor=colors.white, textAnchor="middle"))
        d.add(String(x + ow / 2, 9, sub, fontName="Sans", fontSize=6.2, fillColor=colors.white, textAnchor="middle"))
    return d


# ------------------------------------------------------------------------------------------------- content

story.append(NextPageTemplate("body"))
story.append(PageBreak())

p('<font name="Sans-Bold" size="20">Contents</font>', ParagraphStyle("ct", parent=h1))
toc = TableOfContents()
toc.levelStyles = [toc1, toc2]
story.append(toc)
story.append(PageBreak())

heading("About this guide")
p("This guide takes Warrant from the repository to a production deployment on Google Cloud, explains what to add to "
  "make that deployment production-grade for your organisation, and shows how applications and AI agents use Warrant "
  "in real time. Every command refers to files in the repository; nothing in this guide is a secret, and no step asks "
  "you to put a credential in a file, a command line or a chat.")
table(["If you are…", "Read"], [
    ["The engineer deploying Warrant", "Sections 1, 2, 3 and 4"],
    ["The team operating it", "Sections 4, 6, 8 and the runbooks in <i>docs/runbooks</i>"],
    ["An application or agent developer", "Sections 1, 5 and 6"],
    ["Evaluating the demo locally", "Section 7"],
], [1.2, 1.8])
callout("note", "Shell examples use Bash (Cloud Shell, Linux, macOS, or Git Bash on Windows). Replace values written "
        "in capitals or between angle brackets, for example " + c("PROJECT_ID") + " or " + c("<domain>") + ".")

# 1 ---------------------------------------------------------------------------------------------------------
heading("1. What you are deploying")
p("Warrant is an authorization layer for AI agents. An agent never holds the credentials of the systems it works on. "
  "Instead it carries a <b>warrant</b>: a signed statement of who asked for the work (the principal), what they asked "
  "for in their own words (the mandate), what the agent may do (scope) and how much (row, spend and irreversibility "
  "ceilings). Every tool call passes through the <b>gateway</b>, which checks the warrant, decides, injects the real "
  "credential only when the call is allowed, and records the decision in a tamper-evident audit chain.")
story.append(architecture())
p("Figure 1. Production topology. Only the HTTPS load balancer is reachable from the internet; data stores have no "
  "public address; the classifier accepts calls only from the gateway.", small)

heading("Components", 2)
table(["Component", "Runs on", "What it does"], [
    ["pep-gateway", "Cloud Run, min 2 instances", "Verifies warrants and proofs, derives the verb, decides (L0/L1/L2), fetches the target credential from Secret Manager, forwards, parks escalations, emits audit events."],
    ["control-plane", "Cloud Run", "Issues, derives and revokes warrants; compiles, replays and publishes policy; approvals; audit chain with KMS-signed heads; admin and analytics APIs."],
    ["classifier", "Cloud Run, internal only", "Scores blast radius and intent drift (heuristic, or self-hosted Gemma); writes approval-card text with Gemini on Vertex AI from metadata and counts only."],
    ["console", "Cloud Run", "Dashboard, approvals, policy editor with live replay, decision explorer, admin. Google sign-in; the browser holds only an httpOnly session cookie."],
    ["warrant-migrate", "Cloud Run job", "Applies database migrations as the schema owner and provisions tenants, then exits."],
    ["Cloud SQL (PostgreSQL 16)", "Regional HA, private IP", "Warrants, policies, escalations, audit chain. IAM database authentication; row-level security per tenant; append-only audit table."],
    ["Memorystore (Redis 7.2)", "Standard HA, TLS + AUTH", "Decision cache, cumulative usage ledgers, single-use request ids, audit stream, revocation and policy push."],
    ["Cloud KMS", "HSM protection", "Per-tenant warrant-signing and audit-signing keys (Ed25519) and the envelope key for parked arguments. Private keys never leave KMS."],
    ["Secret Manager", "Regional replication", "Target-system credentials, OAuth client secret, Redis AUTH string and CA, tenant provisioning file."],
    ["HTTPS load balancer", "Global, Cloud Armor", "TLS 1.2+ (MODERN), OWASP rules for console and API, per-IP rate limits, blocks /internal routes."],
], [1.1, 1.0, 3.1])

heading("How one tool call is decided", 2)
story.append(pipeline())
p("Figure 2. The decision pipeline. The model in L2 can only make a decision stricter than L1 concluded.", small)
numbered([
    "The agent sends the call to " + c("POST /v1/proxy/{tool}") + " with its warrant chain and a fresh Ed25519 proof "
    "of possession over the warrant id, a single-use request id, the time, the tool and the SHA-256 of the arguments.",
    "The gateway verifies signatures, expiry, revocation, delegation depth and the proof. A replayed or altered request "
    "fails here.",
    "The verb is derived from the call itself (a " + c("DELETE") + " is a delete whatever the agent claims), and the "
    "target system's dry run measures how many records would change and whether protected records are among them.",
    "L0 returns a cached decision for an identical call under the same policy version; L1 evaluates the tenant's "
    "policy deterministically; L2 runs only when L1 cannot decide alone.",
    "Allow: the credential is fetched from Secret Manager for this request only and the call is forwarded. Escalate: "
    "the call is parked in Postgres and a card goes to an approver. Deny: a reason code from a closed set is returned.",
    "Every decision is appended to the tenant's hash chain; irreversible actions are never allowed if that record "
    "cannot be written.",
])

heading("Guarantees you can rely on", 2)
bullets([
    "<b>No standing credentials in agents.</b> A compromised agent can request; it cannot act.",
    "<b>Narrowing only.</b> A sub-agent's warrant can only shrink scope, ceilings, lifetime and delegation depth; a "
    "widened child fails verification.",
    "<b>Stricter-only model.</b> A degraded or manipulated classifier causes extra escalations, never an unsafe allow.",
    "<b>Cumulative ceilings.</b> 300 deletes of 5 rows exhaust a 250-row ceiling at row 250.",
    "<b>Timeouts deny.</b> An escalation nobody answers is denied, never approved.",
    "<b>Tamper evidence.</b> Editing any audit row, even as a database superuser, is reported at that row's index.",
])

# 2 ---------------------------------------------------------------------------------------------------------
heading("2. Before you start")
heading("Tools", 2)
table(["Tool", "Used for"], [
    ["Google Cloud SDK (" + c("gcloud") + ")", "Project setup, secrets, the migration job, DNS checks. Cloud Shell has it preinstalled."],
    ["Terraform 1.7 or later", "All infrastructure in " + c("deploy/terraform") + " (Google provider 6.x, locked in .terraform.lock.hcl)."],
    ["Docker with Buildx", "Building the four service images (or use Cloud Build)."],
    ["Java 21", "Only for the " + c("warrant") + " command-line tool."],
    ["A DNS zone you control", "Three host names: console., api. and pep. under one domain."],
], [1.2, 3.0])
heading("Permissions", 2)
p("The first deployment needs a person with Owner on the new project (or Project IAM Admin, Service Usage Admin, "
  "Cloud SQL Admin, Cloud KMS Admin, Secret Manager Admin, Compute Network Admin, Cloud Run Admin and Artifact Registry "
  "Admin). After that, deployments run from CI through a narrow, keyless deployer identity (Section 4.6).")
heading("Decisions to make first", 2)
table(["Decision", "Default", "Notes"], [
    ["Region", c("asia-south1"), "All regional resources and data stay here. Pick the region closest to your agents and target systems; the gateway is on their hot path."],
    ["Domain", "—", "For example " + c("warrant.example.com") + " gives console.warrant.example.com, api.… and pep.…"],
    ["Tenants", c('["acme"]'), "Each tenant gets its own signing keys, policy, users and audit chain."],
    ["Key protection", c("HSM"), "Use HSM in production. " + c("SOFTWARE") + " is acceptable for staging."],
    ["Classifier backend", c("heuristic"), "Deterministic and model-free. Switch to " + c("gemma") + " after deploying deploy/k8s (Section 4.8)."],
    ["Who approves", "—", "At least two approvers per tenant so an absence does not turn every escalation into a timeout."],
], [0.9, 0.8, 3.0])
callout("security", "Use a dedicated project per environment (for example warrant-prod and warrant-staging). Never "
        "set " + c("WARRANT_ENV") + " to local, demo or test in Google Cloud: those names enable development-only "
        "code paths, and the Terraform configuration refuses them.")

# 3 ---------------------------------------------------------------------------------------------------------
heading("3. Step-by-step deployment")
p("The deployment has three Terraform phases because some things must exist before others can start: images and "
  "secrets before services, and the database schema before the control plane. Plan for about 90 minutes, most of it "
  "waiting for Cloud SQL and the managed certificate.")

step(1, "Create the project", "Create an empty project, link billing, and set the variables used by every later step.")
code("""
export PROJECT_ID=warrant-prod-1234          # globally unique
export REGION=asia-south1
export DOMAIN=warrant.example.com
gcloud projects create "$PROJECT_ID" --name="Warrant"
gcloud billing projects link "$PROJECT_ID" --billing-account=<BILLING_ACCOUNT_ID>
gcloud config set project "$PROJECT_ID"
gcloud services enable serviceusage.googleapis.com cloudresourcemanager.googleapis.com storage.googleapis.com
""")

step(2, "Create the Terraform state bucket", "Terraform state lists every resource; keep it versioned and private.")
code("""
gcloud storage buckets create "gs://$PROJECT_ID-warrant-tfstate" --location="$REGION" \\
  --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update "gs://$PROJECT_ID-warrant-tfstate" --versioning
""")
callout("security", "This configuration never writes your secret values into state. The only generated secrets in "
        "state are the Memorystore AUTH string and CA certificate, which Google creates. Restrict the bucket to the "
        "deployers.")

step(3, "Set up Google sign-in", "The console signs people in with Google; the control plane checks every request against this OAuth client.")
numbered([
    "In the Google Cloud console open <b>Google Auth Platform</b>. Under <b>Branding</b> set the app name "
    "(Warrant) and a support email. Under <b>Audience</b> choose <b>Internal</b> if you use Google Workspace, so only "
    "your organisation can sign in.",
    "Under <b>Clients</b>, create a client of type <b>Web application</b> with the authorised redirect URI "
    + c("https://console.<domain>/api/auth/google/callback") + ".",
    "Copy the <b>Client ID</b> into the Terraform variables (next step). Keep the <b>client secret</b> open for Step 6; "
    "do not save it to a file.",
])

step(4, "Configure Terraform", "Fill in the variables and initialise the backend.")
code("""
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars      # git-ignored
# edit terraform.tfvars:
#   project_id        = "warrant-prod-1234"
#   region            = "asia-south1"
#   image_tag         = "<full git commit SHA, set in Step 7>"
#   domain            = "warrant.example.com"
#   tenants           = ["acme"]
#   oidc_client_id    = "<client id from Step 3>"
#   github_repository = "<owner/repo, or empty to skip CI federation>"
terraform init -backend-config="bucket=$PROJECT_ID-warrant-tfstate"
""")

step(5, "Phase A: foundations", "Enable APIs and create the image registry, the secret containers and the signing keys.")
code("""
terraform apply \\
  -target=google_project_service.enabled \\
  -target=google_artifact_registry_repository.warrant \\
  -target=google_secret_manager_secret.oidc_client_secret \\
  -target=google_secret_manager_secret.provision \\
  -target=google_secret_manager_secret.target \\
  -target=google_kms_crypto_key.warrant_signing \\
  -target=google_kms_crypto_key.audit_signing
""")
p("Terraform warns that " + c("-target") + " is for exceptional use; that is expected while bootstrapping.", small)

step(6, "Add secret values", "Values go straight into Secret Manager from standard input, never through files in the repository or command arguments.")
code("""
# OAuth client secret (paste, then Ctrl-D)
gcloud secrets versions add warrant-console-oidc-client-secret --data-file=-

# Each target-system credential the gateway will inject (one secret per entry in
# target_credentials in secrets.tf). Example: the ERP service token.
gcloud secrets versions add warrant-target-acme-erp-token --data-file=-

# Tenant provisioning file: tenant ids, KMS key versions, first owners/approvers/auditors.
cp provision.example.json provision.json         # git-ignored; replace PROJECT_ID and the people
gcloud secrets versions add warrant-provision --data-file=provision.json
shred -u provision.json 2>/dev/null || rm provision.json
""")
p("The KMS key versions in the provisioning file follow this pattern (version 1 exists as soon as Phase A finishes):", small)
code("projects/PROJECT_ID/locations/asia-south1/keyRings/warrant/cryptoKeys/acme-warrant/cryptoKeyVersions/1\n"
     "projects/PROJECT_ID/locations/asia-south1/keyRings/warrant/cryptoKeys/acme-audit/cryptoKeyVersions/1")
callout("check", c("gcloud secrets versions list warrant-provision") + " shows one ENABLED version.")

step(7, "Build and push the images", "Images are tagged with the commit SHA; the registry refuses to overwrite a tag.")
code("""
cd "$(git rev-parse --show-toplevel)"
export TAG=$(git rev-parse HEAD)
export REGISTRY=$REGION-docker.pkg.dev/$PROJECT_ID/warrant
gcloud auth configure-docker "$REGION-docker.pkg.dev"
docker build --platform linux/amd64 -f deploy/docker/java.Dockerfile --build-arg APP=control-plane -t "$REGISTRY/control-plane:$TAG" .
docker build --platform linux/amd64 -f deploy/docker/java.Dockerfile --build-arg APP=pep-gateway   -t "$REGISTRY/pep-gateway:$TAG" .
docker build --platform linux/amd64 -t "$REGISTRY/classifier:$TAG" apps/classifier
docker build --platform linux/amd64 -t "$REGISTRY/console:$TAG"    apps/console
for image in control-plane pep-gateway classifier console; do docker push "$REGISTRY/$image:$TAG"; done
""")
p("Set " + c("image_tag") + " in terraform.tfvars to the value of " + c("$TAG") + ".")

step(8, "Phase B: network, data and the migration job", "Targeting the job brings up everything the first migration needs and no long-running service yet.")
code("""
cd deploy/terraform
terraform apply -target=google_cloud_run_v2_job.migrate
""")
p("This creates the VPC with private service access and Cloud NAT, the regional Cloud SQL instance (10 to 15 minutes), "
  "Memorystore with TLS and AUTH, the envelope key, the service accounts, the Cloud SQL IAM users and the job.")

step(9, "One-time database bootstrap", "Give the migration identity the right to create the schema. This is the only time a database password exists.")
numbered([
    "Set a temporary password for the built-in user: " + c("gcloud sql users set-password postgres --instance=warrant-pg --prompt-for-password"),
    "Open <b>Cloud SQL → warrant-pg → Cloud SQL Studio</b>, choose database <b>warrant</b>, user <b>postgres</b>.",
    "Paste " + c("deploy/terraform/sql/bootstrap.sql") + " with PROJECT_ID replaced, and run it. It creates the role "
    + c("warrant_app") + ", lets the migration identity create objects and administer that one role, and lets the "
    "runtime identity connect. Neither identity becomes a superuser.",
    "Run the set-password command again and paste a long random value that you do not keep.",
])

step(10, "Run migrations and provision tenants", "The job runs as the schema owner, applies migrations, creates your tenants with their KMS keys, and exits.")
code("""
gcloud run jobs execute warrant-migrate --region="$REGION" --wait
gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="warrant-migrate"' \\
  --limit=50 --format='value(textPayload)' | grep -E "provisioned|migrate-only"
""")
callout("check", "The log shows <i>tenant acme provisioned with Cloud KMS signing keys</i> and <i>migrations applied; "
        "migrate-only mode exits</i>. Run the job again on every release before rolling out services; it is idempotent.")

step(11, "Phase C: services and the edge", "Deploy the four Cloud Run services, the load balancer, Cloud Armor and CI federation.")
code("""
terraform apply
terraform output edge_ip
terraform output kms_key_versions
""")

step(12, "DNS and TLS", "Point the three host names at the load balancer and wait for the Google-managed certificate.")
code("""
# A records: console.<domain>, api.<domain>, pep.<domain>  ->  <edge_ip>
gcloud compute ssl-certificates describe warrant-edge --global --format="value(managed.status)"
# repeat until ACTIVE (usually 15-60 minutes after DNS resolves)
curl -s https://api.$DOMAIN/health && curl -s https://pep.$DOMAIN/health
curl -s -o /dev/null -w "%{http_code}\\n" https://api.$DOMAIN/internal/bundle   # 404: blocked at the edge
""")

step(13, "Sign in and configure the tenant", "Configuration happens in the console, as the owners from the provisioning file.")
numbered([
    "Open " + c("https://console.<domain>") + " and sign in with Google as a provisioned owner.",
    "<b>Admin → Register or update a tool</b>: paste each tool definition (Section 5.2). The credential is a reference: "
    + c("gcp-secret://projects/PROJECT_ID/secrets/warrant-target-acme-erp-token/versions/latest") + ".",
    "<b>Admin → Register or update an agent</b>: name, the build hash of the deployed agent artifact, and the largest "
    "scope it may ever receive.",
    "<b>Policy</b>: paste or edit the tenant policy (start from " + c("policies/examples/vendors.policy") + "), check that "
    "it compiles, that its inline tests pass and what the live replay would change, then publish. Publishing requires "
    "the security admin role.",
])
screenshot("policy.png", "Figure 3. The policy editor compiles as you type, runs inline tests and replays the change "
           "against recent real decisions before you publish.")

step(14, "Smoke test", "Prove the full path: issue a warrant, make allowed and refused calls, and verify the audit chain.")
p("Automation and the command-line tool authenticate with a Google ID token for a service account that is registered as "
  "a console user (for example an auditor account listed under " + c("auditors") + " in the provisioning file):")
code("""
gcloud iam service-accounts create warrant-auditor-bot
# list warrant-auditor-bot@PROJECT_ID.iam.gserviceaccount.com under "auditors" in the provisioning file
gcloud iam service-accounts add-iam-policy-binding warrant-auditor-bot@$PROJECT_ID.iam.gserviceaccount.com \\
  --member="user:$(gcloud config get-value account)" --role=roles/iam.serviceAccountTokenCreator
export WARRANT_TOKEN=$(gcloud auth print-identity-token \\
  --impersonate-service-account=warrant-auditor-bot@$PROJECT_ID.iam.gserviceaccount.com \\
  --audiences=<OAUTH_CLIENT_ID> --include-email)
export WARRANT_CONTROL_PLANE_URL=https://api.$DOMAIN WARRANT_TENANT=acme
./scripts/warrant audit verify
./scripts/warrant audit trace --target acme-prod:vendors --limit 5
""")
callout("check", "The console dashboard shows decisions arriving, the audit chain marked <b>Intact</b>, and "
        + c("audit verify") + " ends with <i>chain verified</i>.")

# 4 ---------------------------------------------------------------------------------------------------------
heading("4. Making it production-grade")
p("The Terraform configuration already applies the controls in the left column. The right column lists what each "
  "organisation should add or decide; most are policy and process rather than code.", lead)
heading("4.1 Security controls", 2)
table(["Area", "Already in place", "Add for your organisation"], [
    ["Identity", "One service account per workload; keyless CI through Workload Identity Federation; Cloud SQL IAM auth; one-hour console sessions; high-severity approvals need a sign-in from the last five minutes.",
     "Enforce 2-Step Verification or security keys for approvers and admins. Organisation policies: " + c("iam.disableServiceAccountKeyCreation") + ", " + c("sql.restrictPublicIp") + ", " + c("gcp.resourceLocations") + ". Review console users quarterly."],
    ["Network", "No public IP on Cloud SQL or Memorystore; Cloud Run ingress limited to the load balancer and VPC; classifier internal-only with IAM; Cloud Armor WAF and rate limits; TLS 1.2+ MODERN; default-deny firewall.",
     "A VPC Service Controls perimeter around Cloud KMS, Secret Manager, Cloud SQL Admin and Vertex AI. Restrict console. to corporate ranges in Cloud Armor. Enable Cloud Armor Adaptive Protection."],
    ["Keys", "HSM-protected Ed25519 signing keys per tenant; separate audit key; envelope key rotates every 90 days; private keys never leave KMS.",
     "Alert on KMS data-access logs outside the control plane's identity. Rotate signing keys yearly (runbook rotate-signing-keys.md)."],
    ["Data", "Regional HA, point-in-time recovery (7 days), 30 daily backups; row-level security per tenant; append-only audit table; parked arguments envelope-encrypted.",
     "Customer-managed encryption keys for Cloud SQL, Memorystore and Artifact Registry if required. Cross-region backup copies. A retention-locked bucket for exported evidence packs."],
    ["Secrets", "All credentials in Secret Manager, fetched by reference per request; never logged or returned; gitleaks over full history in CI.",
     "Rotate target credentials on a schedule; the gateway reads " + c("versions/latest") + ", so rotation needs no deploy."],
    ["Supply chain", "Immutable image tags; vulnerability scanning; pinned base images; non-root containers; read-only file systems where possible.",
     "Binary Authorization requiring a CI attestation; SBOM generation; automated dependency updates."],
], [0.75, 2.1, 2.1])

heading("4.2 Reliability", 2)
bullets([
    "<b>Gateway</b>: at least two warm instances, up to 50, 250 concurrent requests each. Raise " + c("pep_min_instances") + " ahead of known load.",
    "<b>Policy keeps working when the control plane does not</b>: gateways serve their cached policy bundle and log "
    + c("POLICY STALE") + " after five minutes without a refresh. Escalations need the control plane; if a call cannot "
    "be parked it is denied with " + c("AUDIT_UNAVAILABLE") + ".",
    "<b>Classifier down</b>: the gateway's circuit opens and the policy's " + c("on classifier_unavailable") + " block "
    "applies (in the example: reads allowed, everything else escalates). Nothing becomes more permissive.",
    "<b>Audit store down</b>: irreversible actions are denied; reversible allows are buffered and flushed when it returns.",
    "<b>Parked escalations survive restarts</b>: they live in Postgres; a released call carries an idempotency key so a "
    "retried release executes once.",
    "<b>Disaster recovery</b>: restore Cloud SQL to a point in time or from backup, redeploy services from the same image "
    "tags; signing keys and secrets are regional services that are not affected by a database restore.",
])
heading("4.3 Service levels to monitor", 2)
table(["Objective", "Target", "Measure"], [
    ["Gateway availability", "99.95% monthly", "Cloud Run request count by status (5xx excluding deliberate 503 fail-closed)."],
    ["L0/L1 decision latency", "p95 < 25 ms in region", "Cloud Run request latency for /v1/proxy and /v1/authorize; dashboard \"L0/L1 p95\"."],
    ["L2 decision latency", "p95 < 600 ms", "Dashboard \"L2 p95\"."],
    ["Time to a human decision", "Median < 5 minutes", "Escalation created to decided; timeouts are denials and should be rare."],
    ["Audit chain integrity", "Always intact", "Dashboard chain status; " + c("AUDIT CHAIN BROKEN") + " log alert."],
], [1.3, 1.0, 2.6])

heading("4.4 Alerts", 2)
p("Create log-based metrics and alert on them. Example for the most important one:")
code("""
gcloud logging metrics create warrant_audit_chain_broken \\
  --description="Warrant audit chain verification failed" \\
  --log-filter='resource.type="cloud_run_revision" AND textPayload:"AUDIT CHAIN BROKEN"'
# then in Monitoring > Alerting, create a policy on
#   logging/user/warrant_audit_chain_broken > 0  and route it to on-call
""")
table(["Log text or metric", "Meaning", "Severity"], [
    [c("AUDIT CHAIN BROKEN"), "An audit row was altered. Follow runbook audit-chain-broken.md.", "Page, security incident"],
    [c("POLICY STALE"), "A gateway has not refreshed policy for over five minutes.", "Page"],
    [c("audit store unavailable"), "Audit events are being buffered; irreversible actions are denied.", "Page"],
    [c("classifier circuit opened"), "L2 degraded to the policy's fallback; more escalations expected.", "Ticket"],
    [c("rejected untrusted internal call"), "Something other than the gateway called an internal route.", "Security review"],
    ["Cloud Run 5xx > 1% (5 min)", "Service errors.", "Page"],
    ["Cloud SQL CPU > 80%, Redis memory > 80%", "Capacity.", "Ticket"],
    ["Pending escalations > 20", "Approvers are falling behind; calls will time out (deny).", "Ticket"],
], [1.6, 2.6, 1.0])

heading("4.5 Governance", 2)
bullets([
    "Policy authors are not publishers: developers edit and replay, security admins publish. Every publish is recorded "
    "in the audit chain.",
    "Changing a tenant's fail mode needs two security admins (a change request and a different approver).",
    "Suspending an agent revokes all of its live warrants at once (Admin → Suspend agent).",
    "Auditors are read-only and can never be approvers; this is enforced in the database.",
    "Export evidence packs (" + c("warrant audit export --format evidence-pack") + ") for audits; they can be verified "
    "with " + c("packages/chain-verify") + " on any machine, without Warrant.",
])

heading("4.6 Release process", 2)
p("The repository's " + c(".github/workflows/ci.yml") + " runs, in order: gitleaks over the full history, Java build and "
  "tests with real Postgres and Redis, the adversarial suite, the standalone chain verifier, classifier tests and the "
  "100% recall gate, the console build, then the full demo, chaos and accessibility tests. On " + c("main") + " it "
  "builds and pushes images, runs the migration job and deploys. Set these repository variables: " + c("GCP_PROJECT_ID")
  + ", " + c("GCP_REGION") + ", " + c("GCP_WORKLOAD_IDENTITY_PROVIDER") + " and " + c("GCP_DEPLOYER_SA") + " (Terraform outputs).")
p("For a cautious rollout of the gateway, deploy without traffic and shift it gradually:")
code("""
gcloud run deploy warrant-pep-gateway --region=$REGION \
  --image=$REGISTRY/pep-gateway:$TAG --no-traffic --tag=canary
gcloud run services update-traffic warrant-pep-gateway --region=$REGION --to-tags=canary=10
# after the checks pass
gcloud run services update-traffic warrant-pep-gateway --region=$REGION --to-latest
# rollback
gcloud run services update-traffic warrant-pep-gateway --region=$REGION \
  --to-revisions=<previous-revision>=100
""")
callout("warning", "Database migrations must be backward compatible with the previous release (add, then remove in a "
        "later release), because the migration job runs before the new services receive traffic.")

heading("4.7 Load test before launch", 2)
code("""
# against a staging gateway, with a warrant and agent key for a read-only tool
export WARRANT_TOKEN=<warrant chain> WARRANT_AGENT_KEY_FILE=<agent key PEM>
python load/presign.py 23000 > load/requests.json        # proofs are single-use and expire after 60 s
k6 run -e PEP=https://pep.<domain> load/l1-path.js        # fails if p95 >= 25 ms
""")

heading("4.8 Optional: self-hosted Gemma for L2", 2)
p("To keep tool-call arguments inside your network while using a model for L2, deploy Gemma 3 on GKE Autopilot with "
  "L4 GPUs (" + c("deploy/k8s") + ") behind an internal load balancer, then set " + c('classifier_backend = "gemma"')
  + " and " + c("gemma_endpoint") + ". Model output is parsed and validated; anything malformed becomes low confidence, "
  "which escalates.")

heading("4.9 Never do these", 2)
bullets([
    "Give an agent a target credential \"just for this one job\". Register the tool instead.",
    "Grant " + c("warrant_app") + " UPDATE or DELETE on " + c("audit_entries") + ", or disable its triggers.",
    "Expose the classifier publicly or remove its IAM requirement.",
    "Use a development environment name or development keys in Google Cloud.",
    "Publish a policy whose replay shows newly allowed calls you have not reviewed.",
])

# 5 ---------------------------------------------------------------------------------------------------------
heading("5. Using Warrant in your applications")
p("Three parties take part: a <b>person</b> starts a task, your <b>application</b> obtains a warrant for that task, and "
  "the <b>agent</b> presents the warrant on every tool call. Your application never forwards credentials to the agent.", lead)

heading("5.1 Integration patterns", 2)
table(["Pattern", "When to use it", "Endpoint"], [
    ["Proxy (recommended)", "The gateway authorizes and forwards; the agent never has a network path or credential to the target.", c("POST /v1/proxy/{tool}")],
    ["MCP", "Agents built on the Model Context Protocol: point the MCP client at the gateway.", c("POST /v1/mcp") + " (tools/call)"],
    ["Authorize only", "A legacy integration that must call the target itself. Weaker: the caller holds a credential.", c("POST /v1/authorize")],
], [1.0, 2.6, 1.3])

heading("5.2 Connect a target system", 2)
numbered([
    "Put its credential in Secret Manager: add the name to " + c("target_credentials") + " in "
    + c("deploy/terraform/secrets.tf") + ", apply, then add the value with " + c("gcloud secrets versions add") + ".",
    "Make the target accept only the gateway: allow-list the Cloud NAT egress address, and keep the credential only in "
    "Secret Manager. A direct call without the gateway then fails.",
    "Optionally give it a dry-run endpoint. Warrant posts " + c('{"verb": …, "arguments": …}') + " and expects "
    + c('{"available": true, "estimated_rows": N, "protected": {"class": count}, "safe_ids": [...]}') + ". Without it "
    "the magnitude is unknown, and the policy can escalate on that.",
    "Register the tool in the console (Admin) with a definition like the one below.",
])
code("""
{
  "id": "sql.execute",
  "protocol": "mcp",
  "derivation": "SQL",
  "sql_argument": "q",
  "endpoint": "https://erp.internal.example.com/tools/sql.execute",
  "dry_run_endpoint": "https://erp.internal.example.com/tools/dry_run",
  "credential_ref": "gcp-secret://projects/PROJECT_ID/secrets/warrant-target-acme-erp-token/versions/latest",
  "target_prefix": "acme-prod",
  "target_tags": { "acme-prod:ledger": ["ledger"] },
  "alternatives": [ { "for_verb": "delete", "resource": "vendors", "tool": "vendors.archive",
                      "argument": "ids", "action_label": "Archive {rows} safe" } ]
}
""")

heading("5.3 Write the policy", 2)
p("Policies are short, ordered rules per tool and verb, with inline tests. Deny rules run first, then escalate, then "
  "allow; anything unmatched is not allowed.")
code("""
tool "sql.execute" {
  verb "select" { allow }
  verb "update" { allow if rows <= ceiling.rows }
  verb "delete" {
    deny     if target.tagged("ledger")
    escalate if irreversible
    escalate if rows > ceiling.rows
    escalate if affected.any(protected: ["open_invoice", "under_audit"])
  }
  verb "drop"   { deny }
}

guardrail "stay_on_mandate" {          # evaluated only for calls that reach L2
  deny     if drift_score > 0.75
  escalate if drift_score > 0.45
}

on classifier_unavailable {
  verb "select" { allow }
  default       { escalate }
}

test "bulk delete escalates" {
  given tool "sql.execute" verb "delete" rows 1284 irreversible true
  with  warrant scope ["vendors.read", "vendors.archive"] ceiling rows 250
  expect escalate reason CEILING_EXCEEDED
}
""")
p("Check locally with " + c("./scripts/warrant policy lint|test FILE") + ", then replay and publish in the console.")

heading("5.4 Start a task: issue a warrant", 2)
p("When a person starts a task in your application, your backend requests a warrant with that person's Google ID token "
  "(audience: Warrant's OAuth client ID), so the warrant names them as the accountable principal. For scheduled work, "
  "use a service account registered as a console user; the service account is then the principal of record.")
code("""
POST https://api.<domain>/v1/warrants
Authorization: Bearer <ID token of the person starting the task>
X-Warrant-Tenant: acme
Content-Type: application/json

{ "agent": "vendor-hygiene",
  "build_hash": "sha256:<digest of the deployed agent>",
  "mandate": "clean up stale vendor records",
  "scope": ["vendors.read", "vendors.archive"],
  "ceiling": { "rows": 250, "irreversible": false, "spend": 0 },
  "ttl_seconds": 900, "hops": 3,
  "cnf": "<base64url of the agent's Ed25519 public key>" }

201 Created  { "wid": "wrt_…", "token": "wt1.….…", "expires_at": "…" }
""")
p("Hand " + c("token") + " to the agent. A sub-agent obtains a narrower warrant from "
  + c("POST /v1/warrants/{wid}/derive") + ", authenticated by the parent chain and the agent's proof; any attempt to "
  "widen scope, ceilings, lifetime or depth is refused.")

heading("5.5 Make tool calls", 2)
p("<b>Java</b> (" + c("packages/sdk-java") + "):")
code("""
WarrantClient warrant = WarrantClient.builder(URI.create("https://pep.example.com"))
        .warrant(token).agentKey(AgentKey.fromPemFiles(keyPem, publicPem)).build();

String sql = "DELETE FROM vendors WHERE last_activity < now() - interval '18 months'";
switch (warrant.call("sql.execute", Map.of("q", sql))) {
    case ToolResult.Allowed ok      -> handle(ok.body());
    case ToolResult.Denied no       -> report(no.reasonCode(), no.explanation());   // do not retry
    case ToolResult.Escalated wait  -> {
        EscalationStatus s = warrant.await(wait.escalationId(), Duration.ofMinutes(5));
        if (s.approved()) handle(s.result()); else report("APPROVAL_" + s.state(), "");
    }
}
""")
p("<b>Python</b> (" + c("deploy/demo/agent/warrant_client.py") + ", about 150 lines, depends on httpx and cryptography):")
code("""
client = WarrantClient("https://pep.example.com", token, AgentKey.load("/secrets/agent.key.pem"))
result = client.call("sql.execute", {"q": "SELECT id, name FROM vendors WHERE status = 'active'"})
if result.decision == "escalate":
    status = client.wait(result.escalation_id, timeout_s=300)   # rides out gateway restarts
""")
p("<b>Any language</b>: send these headers with " + c('{"arguments": {...}}') + " to " + c("/v1/proxy/{tool}") + ".")
table(["Header", "Value"], [
    [c("X-Warrant"), "The warrant chain as issued (links joined by ~, root first)."],
    [c("X-Request-Id"), "A new id per request, 8 to 64 characters of [A-Za-z0-9_-]. Single use."],
    [c("X-Request-Time"), "UTC time, whole seconds: " + c("2026-11-20T09:15:09Z") + ". Must be within 60 s of the gateway clock."],
    [c("X-Warrant-Proof"), c("v1.") + " + base64url(Ed25519 signature) over " + c("\"warrant-proof/v1\\n\"") + " + canonical JSON of "
     + c("{arg_digest, request_id, tool, ts, wid}") + "."],
    [c("Prefer"), "Optional " + c("wait=N") + ": hold the connection up to N seconds (max 60) if a human must decide."],
], [1.0, 3.6])
p(c("arg_digest") + " is " + c("sha256:") + " + hex SHA-256 of the canonical JSON of the arguments: keys sorted, no "
  "whitespace, integers as plain digits, no binary floating point (send decimals as strings).", small)

heading("5.6 Handle every outcome", 2)
table(["Response", "Meaning", "What the agent should do"], [
    ["200 + " + c("X-Warrant-Decision: allow"), "Forwarded; the body is the target's response.", "Continue."],
    ["403 " + c('"decision": "deny"'), "Refused, with a reason code.", "Stop this action and report the explanation. Retrying does not help."],
    ["202 " + c('"decision": "escalate"'), "Parked for a human; " + c("escalation_id") + " and " + c("expires_at") + " returned.", "Wait (await / poll), or move on and check later. Expiry means denied."],
    ["429 " + c("RATE_LIMITED"), "Per-agent or per-tenant rate limit.", "Back off and retry later."],
    ["5xx", "Gateway or target unavailable. Nothing was forwarded unless the target itself returned the error.", "Retry with backoff; use a new request id."],
], [1.3, 1.8, 2.0])
p("Reason codes (closed set)", h3)
table(["Code", "Meaning"], [
    [c("INVALID_WARRANT"), "Signature, format, key or proof of possession failed."],
    [c("EXPIRED") + " / " + c("REVOKED"), "The warrant's lifetime ended, or it (or an ancestor) was revoked."],
    [c("HOP_LIMIT"), "Delegated deeper than the warrant allows."],
    [c("OUT_OF_SCOPE"), "The derived permission is not in the warrant's scope."],
    [c("CEILING_EXCEEDED"), "Cumulative rows or spend would exceed the warrant's ceiling."],
    [c("IRREVERSIBLE"), "An irreversible action the warrant does not permit."],
    [c("PROTECTED_RECORDS"), "Protected records (for example open invoices) are in the affected set."],
    [c("INTENT_DRIFT"), "The action does not serve the mandate (typical of prompt injection)."],
    [c("LOW_CONFIDENCE"), "The classifier was not confident enough to rely on."],
    [c("AUDIT_UNAVAILABLE"), "The decision could not be recorded durably."],
    [c("APPROVAL_TIMEOUT") + " / " + c("APPROVAL_DENIED"), "Nobody decided in time, or a human said no."],
    [c("RATE_LIMITED"), "Too many requests."],
], [1.6, 3.2])

# 6 ---------------------------------------------------------------------------------------------------------
heading("6. Real-time operation")
heading("6.1 Latency budget", 2)
table(["Path", "Typical", "How to keep it there"], [
    ["L0 cache hit", "a few ms", "Identical call, same warrant and policy version (60 s cache)."],
    ["L1 policy", "p95 < 25 ms in region", "Gateway in the same region as agents and targets; warm instances; Redis in the same VPC."],
    ["L2 model", "p95 < 600 ms", "Only when L1 cannot decide alone; classifier micro-batches for 20 ms; scale GPU replicas for Gemma."],
    ["Human decision", "minutes", "Use " + c("Prefer: wait=N") + " for short holds; otherwise poll with backoff."],
], [1.0, 1.1, 3.0])
heading("6.2 Keeping humans in the loop, live", 2)
screenshot("approval.png", "Figure 4. The approval card. The headline states the real number; provenance comes verbatim "
           "from the warrant; the safe alternative is offered as a first-class action; the timer shows when it will be "
           "denied automatically.", width=CONTENT_W * 0.80)
bullets([
    "Approvers see new cards immediately in the console; delivery adapters can also post to Google Chat, Slack or email "
    "(configured with webhook secrets in Secret Manager). If every channel fails, the escalation stays pending and then "
    "times out as a denial; it never auto-approves.",
    "Similar calls from one run within two minutes are coalesced into one card.",
    "The gateway holds an agent's connection for up to 60 s with " + c("Prefer: wait=N") + ", so a quick approval returns "
    "the released result in the same request.",
])
heading("6.3 Live decision feed", 2)
screenshot("dashboard.png", "Figure 5. The dashboard: decision counters, pending escalations with time remaining, latency "
           "percentiles, chain health, blast radius prevented, and a live decision stream.", width=CONTENT_W * 0.88)
bullets([
    "The console streams decisions over server-sent events from " + c("GET /v1/decisions/stream") + ".",
    "For SIEM and analytics, export Cloud Logging to BigQuery or Pub/Sub with a log sink, and schedule audit exports "
    "(" + c("warrant audit export --format jsonl") + ") with Cloud Scheduler and a Cloud Run job using the auditor service account.",
    "The decision explorer (Decisions) filters by verdict and stage and verifies the chain on demand.",
])
heading("6.4 Propagation and kill switches", 2)
table(["Change", "Reaches every gateway"], [
    ["Revoke a warrant (and its descendants)", "Pushed immediately; polled every 2 s as a fallback."],
    ["Suspend an agent", "All of its live warrants are revoked at once."],
    ["Publish a policy", "Pushed immediately; bundles polled every 5 s; staleness alert after 5 minutes."],
    ["Rotate a target credential", "Next request (the gateway reads versions/latest, cached up to 5 minutes)."],
], [2.2, 2.8])

# 7 ---------------------------------------------------------------------------------------------------------
heading("7. Local demo and development")
p("The whole system runs on one machine with Docker. Generated local secrets live in " + c(".local/") + " (git-ignored).")
code("""
./scripts/demo-up.sh                                          # build, start, register demo tools/agent/policy
./scripts/demo-reset.sh && ./scripts/demo-run.sh --gate off   # agent holds the credential: 1,284 vendors deleted
./scripts/demo-reset.sh && ./scripts/demo-run.sh --gate on    # injection denied, escalation, 1,072 archived
./scripts/demo-run.sh --gate on --approve console             # decide the card yourself at http://localhost:3000
export WARRANT_DEV_EMAIL=daniel@acme.example WARRANT_TENANT=acme
./scripts/warrant audit verify --from 1 --to 99999
./scripts/demo-tamper.sh                                      # rewrite a row as DB superuser: break reported at its index
./scripts/e2e-escalation.sh && ./scripts/chaos-restart-during-escalation.sh
""")
p("Seeded users: " + c("r.menon@acme.example") + " (approver), " + c("priya@acme.example") + " (security admin, owner), "
  + c("meera@acme.example") + " (developer), " + c("daniel@acme.example") + " (auditor). If a port is in use, set "
  + c("WARRANT_PEP_HOST_PORT") + ", " + c("WARRANT_CP_HOST_PORT") + " or " + c("WARRANT_CONSOLE_HOST_PORT") + ".")

# 8 ---------------------------------------------------------------------------------------------------------
heading("8. Troubleshooting")
table(["Symptom", "Likely cause", "Fix"], [
    ["Phase C fails: Cloud Run revision cannot access a secret", "A secret has no version yet.", "Add the value (Step 6) and re-apply."],
    ["Migration job: permission denied for schema public", "Bootstrap SQL not run, or PROJECT_ID not replaced.", "Run Step 9, then the job again."],
    ["Migration job: runtime database user does not exist", "Cloud SQL IAM users not created.", c("terraform apply -target=google_cloud_run_v2_job.migrate") + " again."],
    ["Control plane: tenant has no KMS key", "Provisioning file missing or wrong key version.", "Fix the file, add a new secret version, rerun the job (existing tenants are never modified)."],
    ["Console sign-in returns to login", "Redirect URI mismatch, or user not provisioned.", "Check the OAuth client's redirect URI; add the user as owner/approver."],
    ["Every request 401 from api.", "ID token audience is not the OAuth client ID, or issuer not trusted for the tenant.", "Use " + c("--audiences=<client id>") + "; check " + c("idp_issuer") + " in the provisioning file."],
    ["Every agent call INVALID_WARRANT", "Clock skew over 60 s, reused request id, or arguments changed after signing.", "Sync the clock (NTP); new request id per call; sign the exact arguments sent."],
    ["Calls escalate with LOW_CONFIDENCE", "Classifier unavailable or the target has no dry run.", "Check the classifier; add a dry-run endpoint for the tool."],
    ["Dashboard shows POLICY STALE", "Gateway cannot reach the control plane.", "Check the control plane and VPC egress; gateways keep serving the cached policy."],
], [1.5, 1.6, 1.9])

# appendix ---------------------------------------------------------------------------------------------------
heading("Appendix: configuration reference")
p("Every variable is set by Terraform in Google Cloud. " + c(".env.example") + " lists the names with empty values; "
  "values never appear in the repository.")
table(["Variable", "Used by", "Purpose"], [
    [c("WARRANT_ENV"), "all", "Environment name; development names are refused in Google Cloud."],
    [c("WARRANT_DB_INSTANCE") + ", " + c("WARRANT_DB_IAM_USER"), "control plane, job", "Cloud SQL connection with IAM authentication."],
    [c("WARRANT_DB_MIGRATE") + ", " + c("WARRANT_MIGRATE_ONLY"), "control plane, job", "Migrations run only in the job."],
    [c("WARRANT_DB_RUNTIME_USER"), "job", "IAM user granted membership of warrant_app."],
    [c("WARRANT_PROVISION_FILE"), "job", "Tenant provisioning file (from Secret Manager)."],
    [c("WARRANT_KMS_ENVELOPE_KEY"), "control plane", "KMS key for envelope encryption of parked arguments."],
    [c("WARRANT_OIDC_AUDIENCE"), "control plane", "OAuth client ID that ID tokens must be issued for."],
    [c("WARRANT_PEP_SERVICE_ACCOUNT"), "control plane", "The only identity allowed on internal routes."],
    [c("WARRANT_CONTROL_PLANE_URL") + ", " + c("WARRANT_CLASSIFIER_URL"), "gateway, console", "Internal service URLs (also ID-token audiences)."],
    [c("WARRANT_REDIS_HOST/PORT/TLS"), "gateway, control plane", "Memorystore; AUTH and CA come from Secret Manager."],
    [c("WARRANT_CLASSIFIER_BACKEND"), "classifier", c("heuristic") + ", " + c("fixture") + " or " + c("gemma") + "."],
    [c("WARRANT_CARD_BACKEND") + ", " + c("WARRANT_GEMINI_*"), "classifier", "Approval-card wording with Gemini on Vertex AI."],
    [c("WARRANT_OIDC_CLIENT_ID/SECRET"), "console", "Google sign-in (secret from Secret Manager)."],
], [1.9, 1.1, 2.4])
p("Further reading in the repository: " + c("README.md") + ", " + c("docs/adr/") + " (design decisions), "
  + c("docs/runbooks/") + " (operations), " + c("deploy/terraform/") + " (infrastructure as code).", small)


# ----------------------------------------------------------------------------------------------- templates

class Guide(BaseDocTemplate):
    heading_count = 0

    def beforeDocument(self):
        Guide.heading_count = 0

    def afterFlowable(self, flowable):
        level = getattr(flowable, "_toc_level", None)
        if level is not None:
            text = flowable.getPlainText()
            Guide.heading_count += 1
            key = f"h{Guide.heading_count}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
            self.notify("TOCEntry", (level, text, self.page, key))


def cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(DARK)
    canvas.rect(0, 0, W, H, stroke=0, fill=1)
    logo = BRAND / "warrant-wordmark-on-dark.png"
    lw = 120 * mm
    canvas.drawImage(str(logo), (W - lw) / 2, H - 95 * mm, width=lw, height=lw * 172 / 1331, mask="auto")
    canvas.setFillColor(colors.HexColor("#ECECE8"))
    canvas.setFont("Sans-Bold", 26)
    canvas.drawCentredString(W / 2, H - 135 * mm, "Deploying Warrant on Google Cloud")
    canvas.setFont("Sans", 12.5)
    canvas.setFillColor(colors.HexColor("#B0B0AA"))
    canvas.drawCentredString(W / 2, H - 146 * mm, "Step-by-step deployment, production hardening,")
    canvas.drawCentredString(W / 2, H - 153 * mm, "and using Warrant in your applications in real time")
    canvas.setStrokeColor(colors.HexColor("#3A3A36"))
    canvas.line(W / 2 - 40 * mm, H - 168 * mm, W / 2 + 40 * mm, H - 168 * mm)
    canvas.setFont("Sans", 9.5)
    canvas.drawCentredString(W / 2, H - 178 * mm, "Version 1.0  ·  20 November 2026")
    canvas.drawCentredString(W / 2, H - 185 * mm, "Companion to the Warrant Project Bible and Build Specification")
    canvas.setFont("Sans", 8)
    canvas.setFillColor(colors.HexColor("#7A7A74"))
    canvas.drawCentredString(W / 2, 22 * mm, "No credential, key, token or connection string appears in this document.")
    canvas.restoreState()


def page(canvas, doc):
    canvas.saveState()
    mark = BRAND / "warrant-mark-on-light.png"
    canvas.drawImage(str(mark), MARGIN, H - 13 * mm, width=9 * mm, height=9 * mm * 283 / 688, mask="auto")
    canvas.setFont("Sans", 7.5)
    canvas.setFillColor(FAINT)
    canvas.drawString(MARGIN + 11 * mm, H - 11.6 * mm, "Warrant  ·  Google Cloud deployment guide")
    canvas.drawRightString(W - MARGIN, H - 11.6 * mm, "v1.0")
    canvas.setStrokeColor(LINE)
    canvas.line(MARGIN, H - 15 * mm, W - MARGIN, H - 15 * mm)
    canvas.drawRightString(W - MARGIN, 10 * mm, str(doc.page))
    canvas.drawString(MARGIN, 10 * mm, "Warrant — authorization for AI agents")
    canvas.restoreState()


doc = Guide(OUT, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=22 * mm, bottomMargin=18 * mm,
            title="Deploying Warrant on Google Cloud", author="Warrant", subject="Deployment, production and integration guide")
frame = Frame(MARGIN, 18 * mm, CONTENT_W, H - 40 * mm, id="body", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
doc.addPageTemplates([PageTemplate(id="cover", frames=[frame], onPage=cover),
                      PageTemplate(id="body", frames=[frame], onPage=page)])
doc.multiBuild(story)
print("wrote", OUT)
