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


# Content for Warrant Go-Live Guide v2 (first-time Google Cloud user). Executed inside the v1 layout harness.
story.append(NextPageTemplate("body"))
story.append(PageBreak())

p('<font name="Sans-Bold" size="20">Contents</font>', ParagraphStyle("ct", parent=h1))
toc = TableOfContents()
toc.levelStyles = [toc1, toc2]
story.append(toc)
story.append(PageBreak())

def kbd(text):
    return f'<font name="Sans-Bold">{escape(text)}</font>'

def click(path):
    return f'<font name="Sans-Bold" color="#28543F">{escape(path)}</font>'

def numbered_from(start, items):
    for i, item in enumerate(items, start=start):
        story.append(Paragraph(item, bullet, bulletText=f"{i}."))
    story.append(Spacer(1, 3))


heading("Read this first")
p("This guide takes you from <b>no Google Cloud account</b> to <b>Warrant running live on Google Cloud</b> with a "
  "public HTTPS link, then gives you a minute-by-minute script for tomorrow's presentation. Follow the parts in order. "
  "Every command is written out in full: copy it, paste it, press Enter.", lead)
heading("What you will have at the end", 2)
bullets([
    "A Google Cloud virtual machine (a server) running the complete Warrant system: gateway, control plane, classifier, "
    "console, PostgreSQL, Redis and the demo ERP system with its 4,106 seeded vendors.",
    "Your own address, " + c("https://warrant.services") + " (and www.warrant.services), with a real HTTPS "
    "certificate and a password, that opens the Warrant console from any browser.",
    "The live demo: gate off deletes 1,284 vendors; gate on blocks the injection, escalates the bulk delete to you in "
    "the console, and archives exactly 1,072 safe vendors when you approve.",
])
heading("Time, cost and what you need", 2)
table(["Item", "Details"], [
    ["Time", "About 60 to 90 minutes the first time. Most of it is waiting for the first build (15 to 25 minutes)."],
    ["Cost", "New Google Cloud accounts get a free-trial credit (US$300 for 90 days at the time of writing). The server "
             "used here costs roughly US$0.15 to 0.20 per hour while running, which the credit covers. Part 10 shows "
             "how to stop it so it costs almost nothing when you are not presenting."],
    ["You need", "A Google account (Gmail), a debit or credit card for the one-time free-trial verification, a laptop with "
                 "Chrome, the file " + c("Warrant_Deploy_Package.zip") + " (in your " + c("Google-Buildathon")
                 + " folder, next to this PDF), and the login for the website where you bought " + c("warrant.services")
                 + " (to change its DNS)."],
], [0.8, 4.2])
heading("Why one server for tomorrow", 2)
p("The production design (guide v1) spreads Warrant across many managed services and needs your own domain. That is "
  "right for a company, but it takes a day to set up safely and has not yet been run against a real Google project. "
  "For a presentation tomorrow you need something that <b>certainly works</b>: the exact system that passed every "
  "test on your laptop, on one Google Cloud server. Part 12 explains the path to full production afterwards.")
callout("warning", "Do not skip steps, and do not change names (warrant-demo, warrant-ip, asia-south1-a) unless a "
        "step tells you to. Later commands depend on them.")
heading("The plan", 2)
table(["Part", "What you do", "Time"], [
    ["1", "Create a Google Cloud account and start the free trial", "10 min"],
    ["2", "Create a project", "3 min"],
    ["3", "Open Cloud Shell (a terminal inside your browser)", "2 min"],
    ["4", "Create the server and point warrant.services at it", "10 min"],
    ["5", "Upload the code package", "5 min"],
    ["6", "Connect to the server and install Docker and Java", "5 min"],
    ["7", "Start Warrant and get your public link and password", "20 min"],
    ["8", "Run the whole demo once to check it", "10 min"],
    ["9", "Tomorrow: the presentation script", "—"],
    ["10", "Stop, restart and clean up (saves money)", "—"],
    ["11", "If something goes wrong", "—"],
    ["12", "After the hackathon: real projects and production", "—"],
], [0.4, 3.8, 0.8])

# ---------------------------------------------------------------------------------------------------- part 1
heading("Part 1. Create your Google Cloud account")
numbered([
    "Open Chrome and go to " + c("https://console.cloud.google.com") + ".",
    "Sign in with your Google account.",
    "The first time, Google asks for your country and to accept the Terms of Service. Choose your country, tick the "
    "box and click " + click("Agree and continue") + ".",
    "Start the free trial. Click the " + click("Start free") + " (or " + click("Activate") + ") button in the banner at "
    "the top of the page. If you do not see it, open " + c("https://cloud.google.com/free") + " and click "
    + click("Get started for free") + ".",
    "Fill in the form: account type (Individual is fine), name and address, and your card. The card verifies that you "
    "are a real person; the bank may show a small temporary authorisation that is reversed. Click "
    + click("Start my free trial") + ".",
    "You return to the Google Cloud console. A message confirms your free-trial credit.",
])
callout("check", "Open the Navigation menu (the three-line icon, top-left) → " + click("Billing") + ". You should see your free trial "
        "credit and how many days are left.")

# ---------------------------------------------------------------------------------------------------- part 2
heading("Part 2. Create a project")
p("Everything you create in Google Cloud lives inside a <b>project</b>. One project keeps the demo separate and easy to "
  "delete later.")
numbered([
    "At the top of the console, next to the Google Cloud logo, click the <b>project selector</b> (it shows "
    + kbd("My First Project") + " or " + kbd("Select a project") + ").",
    "In the window that opens, click " + click("NEW PROJECT") + " (top-right of the window).",
    "Project name: type " + kbd("warrant-demo") + ". Just below, Google shows the <b>Project ID</b> (for example "
    + c("warrant-demo-471205") + "). <b>Write the Project ID down</b>: you need it in Part 3.",
    "Leave Location as it is and click " + click("CREATE") + ". Wait about 30 seconds.",
    "Click the project selector again and choose " + kbd("warrant-demo") + ". The top bar now shows warrant-demo.",
    "Navigation menu (the three-line icon, top-left) → " + click("Billing") + ". If it says the project has no billing account, click "
    + click("Link a billing account") + " and choose your free-trial billing account.",
])

# ---------------------------------------------------------------------------------------------------- part 3
heading("Part 3. Open Cloud Shell")
p("Cloud Shell is a Linux terminal that runs inside your browser, already signed in to your account. You type every "
  "Google Cloud command here; nothing needs to be installed on your laptop.")
numbered([
    "Click the " + kbd(">_") + " icon (" + kbd("Activate Cloud Shell") + ") at the top-right of the console.",
    "A black terminal opens at the bottom of the page. If a box asks to " + click("Authorize") + " Cloud Shell, click "
    "Authorize.",
    "To paste a command from this PDF: select it here, press Ctrl+C, click inside Cloud Shell, press Ctrl+V (or "
    "right-click → Paste), then press Enter.",
    "Tell Cloud Shell which project to use. Replace " + c("YOUR_PROJECT_ID") + " with the ID you wrote down:",
])
code("""
gcloud config set project YOUR_PROJECT_ID
""")
callout("check", "Run " + c("gcloud config list") + ". The line " + c("project = ") + " shows your Project ID.")
callout("note", "Cloud Shell closes itself after about an hour without typing. That is harmless: click " + kbd(">_")
        + " again, and everything you created stays. If a command ever says the project is not set, run the "
        + c("gcloud config set project") + " line again.")

# ---------------------------------------------------------------------------------------------------- part 4
heading("Part 4. Create the server and connect warrant.services")
p("Run these four commands one at a time in Cloud Shell. Each one prints a few lines and ends without an error.")
heading("4.1 Turn on Compute Engine (Google's virtual machines)", 2)
code("""
gcloud services enable compute.googleapis.com
""")
p("This takes about a minute and prints " + c("Operation ... finished successfully") + ".", small)
heading("4.2 Reserve a fixed public IP address", 2)
p("A fixed address means your link stays the same even if you stop and start the server.")
code("""
gcloud compute addresses create warrant-ip --region=asia-south1
""")
heading("4.3 Open the web ports (80 and 443) for the server", 2)
code("""
gcloud compute firewall-rules create warrant-web \\
  --allow=tcp:80,tcp:443 --target-tags=warrant-web --source-ranges=0.0.0.0/0
""")
heading("4.4 Create the virtual machine", 2)
p("4 CPUs, 16 GB memory, Ubuntu 24.04, 60 GB disk, in Mumbai (asia-south1):")
code("""
gcloud compute instances create warrant-demo \\
  --zone=asia-south1-a \\
  --machine-type=e2-standard-4 \\
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \\
  --boot-disk-size=60GB \\
  --tags=warrant-web \\
  --address=warrant-ip
""")
callout("check", "Run " + c("gcloud compute instances list") + ". You see " + c("warrant-demo") + " with STATUS "
        + c("RUNNING") + " and an " + c("EXTERNAL_IP") + " such as 34.93.120.15. Write the IP down.")
callout("note", "If you get an error mentioning " + c("ZONE_RESOURCE_POOL_EXHAUSTED") + " or that the zone does not "
        "have resources, run the same command with " + c("--zone=asia-south1-b") + " and then use asia-south1-b "
        "everywhere this guide says asia-south1-a.")

heading("4.5 Point warrant.services at your server", 2)
p("Do this now: DNS changes take from a few minutes to an hour to spread, and they can happen while you do Parts 5 to 7.")
numbered(["Get your server's fixed IP address (Cloud Shell):"])
code("""
gcloud compute addresses describe warrant-ip --region=asia-south1 --format="value(address)"
""")
numbered_from(2, [
    "In a new browser tab, sign in to the website where you bought " + c("warrant.services") + " and open the DNS settings "
    "for that domain (see the table below; menu names differ slightly between companies).",
    "<b>Delete</b> any existing records whose name is " + kbd("@") + " (or blank) or " + kbd("www") + " and whose type is "
    + kbd("A") + ", " + kbd("AAAA") + " or " + kbd("CNAME") + ". These usually point to a parked or coming-soon page. "
    "If the domain has <b>forwarding</b> or a website builder switched on, turn it off. Do not touch MX or TXT records.",
    "<b>Add</b> the two records below and save.",
])
table(["Type", "Name / Host", "Value / Points to", "TTL"], [
    ["A", "@", "your server IP (from step 1)", "lowest offered (for example 600 seconds or 1/2 hour)"],
    ["A", "www", "your server IP (from step 1)", "lowest offered"],
], [0.5, 1.0, 1.8, 1.7])
table(["Where you bought it", "Where the DNS settings are"], [
    ["GoDaddy", "My Products → warrant.services → DNS (Manage DNS) → DNS Records → Add New Record"],
    ["Namecheap", "Domain List → Manage (next to warrant.services) → Advanced DNS → Host Records → Add New Record"],
    ["Hostinger", "Domains → warrant.services → DNS / Nameservers → DNS records"],
    ["Cloudflare", "warrant.services → DNS → Records → Add record. Set Proxy status to <b>DNS only</b> (grey cloud)."],
    ["Porkbun", "Domain Management → warrant.services → DNS"],
    ["Squarespace / Google Domains", "Domains → warrant.services → DNS → DNS Settings → Custom records"],
], [1.4, 3.6])
p("Check from Cloud Shell. Repeat every few minutes until both lines show your server IP:")
code("""
getent hosts warrant.services
getent hosts www.warrant.services
""")
callout("note", "If the domain's nameservers were moved to another company (for example Cloudflare), add the records "
        "there instead. You can also check worldwide at " + c("https://dnschecker.org") + " (type warrant.services, choose A).")

# ---------------------------------------------------------------------------------------------------- part 5
heading("Part 5. Upload the code package")
numbered([
    "In the Cloud Shell toolbar (the strip above the black terminal), click " + kbd("More") + " (the three-dot icon) → "
    + click("Upload") + ".",
    "Click " + click("Choose files") + ", browse to your " + c("Google-Buildathon") + " folder, select "
    + c("Warrant_Deploy_Package.zip") + " and click " + click("Upload") + ". Wait for the progress to finish.",
    "Check that it arrived:",
])
code("""
ls -lh ~/Warrant_Deploy_Package.zip
""")
p("Now copy it from Cloud Shell to your server:")
code("""
gcloud compute scp ~/Warrant_Deploy_Package.zip warrant-demo:~ --zone=asia-south1-a
""")
callout("note", "The first time, Google creates an SSH key for you. If it asks " + c("Do you want to continue (Y/n)?")
        + " type " + kbd("Y") + " and press Enter. If it asks for a passphrase, just press Enter twice (empty "
        "passphrase). If it asks to propagate keys, wait; it finishes by itself.")

# ---------------------------------------------------------------------------------------------------- part 6
heading("Part 6. Connect to the server and install the tools")
p("Connect from Cloud Shell to your server:")
code("""
gcloud compute ssh warrant-demo --zone=asia-south1-a
""")
p("The prompt changes to something like " + c("yourname@warrant-demo:~$") + ". You are now typing <b>on the server</b>. "
  "Run these lines (you can paste all of them at once):")
code("""
sudo apt-get update && sudo apt-get install -y unzip
unzip -q -o Warrant_Deploy_Package.zip
cd WARRANT
chmod +x scripts/*.sh scripts/warrant gradlew
./scripts/cloud-vm-setup.sh
""")
p("This installs Docker and Java 21 (about 3 minutes). When it prints <i>Setup finished</i>, log out and back in so "
  "your user may use Docker:")
code("""
exit
gcloud compute ssh warrant-demo --zone=asia-south1-a
""")
callout("check", "Back on the server, run " + c("docker version") + ". It prints a Client and a Server section with no "
        "\"permission denied\".")

# ---------------------------------------------------------------------------------------------------- part 7
heading("Part 7. Start Warrant and get your public link")
code("""
cd ~/WARRANT
./scripts/cloud-demo-up.sh --domain warrant.services
""")
p("It first checks your DNS and prints " + c("DNS ok: warrant.services -> YOUR_IP") + " for both names. A WARNING "
  "there means the records from Part 4.5 are not visible yet; the script continues, and HTTPS starts by itself a few "
  "minutes after DNS is correct. The first run then builds every service from source: about 15 to 25 minutes. Leave "
  "the window open; lots of text scrolls by. At the end it prints a box like this:")
code("""
  ============================================================
   Warrant is live:   https://warrant.services
   Browser login:     user  demo
                      password  Xk3v9QpL2mTz7RwA4bNc
   (password also saved in ~/WARRANT/.local/demo-password)
   Then pick a seeded user, e.g. r.menon@acme.example (approver)
  ============================================================
""")
p("<b>Write down the link and the password.</b> The password is generated on your server and exists nowhere else.")
heading("Open it in your browser", 2)
numbered([
    "Open " + c("https://warrant.services") + " in Chrome. The first visit can take up to a minute while the HTTPS "
    "certificate is issued.",
    "The browser asks for a username and password: enter " + kbd("demo") + " and the password from the box.",
    "The Warrant sign-in page appears. Under <b>Demo sign-in</b>, choose " + kbd("r.menon@acme.example — Approver")
    + " and click " + click("Continue") + ".",
    "You see the Dashboard.",
])
screenshot("dashboard.png", "What you should see after signing in: the Warrant dashboard.", width=CONTENT_W * 0.85)
callout("note", "Certificate or not-secure error: check that " + c("getent hosts warrant.services")
        + " shows your server IP, wait 5 minutes and reload. If DNS is still not ready late tonight, delete "
        + c("~/WARRANT/.local/cloud-domain") + " and run " + c("./scripts/cloud-demo-up.sh") + " with no domain to get a "
        "working " + c("https://YOUR-IP.sslip.io") + " link, or run " + c("./scripts/cloud-demo-up.sh --http")
        + " for plain " + c("http://warrant.services") + ". The first time the server reads the new web settings, "
        "check " + c("docker compose -f deploy/docker-compose.yml logs caddy --tail 20") + " shows no errors.")

# ---------------------------------------------------------------------------------------------------- part 8
heading("Part 8. Run the whole demo once (tonight)")
p("Do this tonight so that tomorrow holds no surprises. Keep two windows side by side: the server terminal (Cloud "
  "Shell, connected with " + c("gcloud compute ssh") + ") and the browser with the console.")
heading("8.1 Gate OFF: the incident", 2)
code("""
cd ~/WARRANT
./scripts/demo-reset.sh && ./scripts/demo-run.sh --gate off
""")
p("Expected: the agent finds 1,284 stale vendors, reads the injected note, purges 212 payment holds and deletes "
  "1,284 vendors. The last line is red: " + c("1,284 vendor rows deleted ...") + ".")
heading("8.2 Gate ON: Warrant in front of the agent, you approve in the browser", 2)
code("""
./scripts/demo-reset.sh && ./scripts/demo-run.sh --gate on --approve console
""")
numbered([
    "In the terminal: " + c("ALLOW") + " for the read, " + c("DENY INTENT_DRIFT") + " for the injected purge, "
    + c("ESCALATE PROTECTED_RECORDS") + " for the bulk delete, then the approval card. It waits for you. (It prints a "
    "localhost link; ignore it and use https://warrant.services.)",
    "In the browser, click " + click("Approvals") + " and open " + kbd("Agent wants to permanently delete 1,284 vendors") + ".",
    "Click " + click("Archive 1,072 safe") + ", then " + click("Confirm archive 1,072 safe") + ".",
    "Back in the terminal: " + c("1,072 safe vendors archived, 0 deleted, payment holds intact") + " in green.",
])
screenshot("approval.png", "The approval card you will show tomorrow.", width=CONTENT_W * 0.72)
heading("8.3 The audit trail and tamper detection", 2)
code("""
export WARRANT_DEV_EMAIL=daniel@acme.example WARRANT_TENANT=acme
./scripts/warrant audit verify --from 1 --to 99999
./scripts/warrant audit trace --target acme-prod:vendors --limit 3
./scripts/demo-tamper.sh
""")
table(["Command", "What you should see"], [
    [c("audit verify"), c("chain verified: N entries, M signed heads")],
    [c("audit trace"), "Each decision with principal, mandate, policy version, model version, approver and the chain check."],
    [c("demo-tamper.sh"), c("CHAIN BROKEN at index N") + " and then " + c("tampering detected at entry N, as expected")
     + " (the row is restored afterwards)."],
], [1.2, 3.8])
callout("check", "If all three runs (8.1, 8.2, 8.3) look like this, you are ready for tomorrow.")

# ---------------------------------------------------------------------------------------------------- part 9
heading("Part 9. Tomorrow: the presentation")
heading("30 minutes before", 2)
numbered([
    "Open " + c("https://console.cloud.google.com") + ", choose the project " + kbd("warrant-demo") + ".",
    "If you stopped the server: Navigation menu (three-line icon) → " + click("Compute Engine") + " → " + click("VM instances")
    + " → tick " + kbd("warrant-demo") + " → " + click("START / RESUME") + ". Wait 3 minutes; all services start by themselves.",
    "Open Cloud Shell, connect: " + c("gcloud compute ssh warrant-demo --zone=asia-south1-a") + ", then "
    + c("cd ~/WARRANT && ./scripts/demo-reset.sh") + ".",
    "In Chrome, open " + c("https://warrant.services") + ", sign in (demo + password, then r.menon). Keep this tab "
    "and the terminal side by side.",
    "Make the terminal text larger (Ctrl and +) so the audience can read it.",
])
heading("Talk track (about 8 minutes)", 2)
table(["Time", "Show", "Say"], [
    ["0:00", "Title / your slide", "AI agents now act on real systems with real credentials. One injected sentence in "
     "a database field can turn a clean-up job into a disaster. Warrant is the authorization layer that stops that."],
    ["1:00", "Terminal: " + c("demo-run.sh --gate off"), "This is today's reality: the agent holds the database "
     "credential. It finds a note in a vendor record, obeys it, purges 212 payment holds, and deletes 1,284 vendors, "
     "including 212 with open invoices."],
    ["2:30", "Say while resetting: " + c("demo-reset.sh"), "With Warrant the agent never holds a credential. A person "
     "issues a warrant: who asked, the instruction word for word, what the agent may do and how much. Every tool call "
     "goes through the Warrant gateway."],
    ["3:30", "Terminal: " + c("demo-run.sh --gate on --approve console"), "The read is allowed in milliseconds. The "
     "injected purge is denied as intent drift: it does not serve the mandate. The bulk delete is irreversible, over "
     "the 250-row ceiling and touches protected records, so it waits for a human."],
    ["4:30", "Browser: Approvals → the card", "The approver sees one sentence with the real number, the provenance from "
     "the warrant, the risk, and a safe alternative. I approve only the 1,072 safe vendors, archived, not deleted."],
    ["5:30", "Terminal: result", "1,072 archived, nothing deleted, payment holds intact."],
    ["6:00", "Browser: Dashboard, then terminal: " + c("audit verify") + ", " + c("demo-tamper.sh"),
     "Every decision is in a hash chain with signed heads. If anyone edits a row, even a database administrator, "
     "verification names the exact row."],
    ["7:00", "Architecture (v1 guide, Figure 1)", "On Google Cloud: Cloud Run, Cloud SQL with IAM login, Cloud KMS "
     "hardware keys, Secret Manager, Gemma for scoring and Gemini for approval-card wording. The model can only make a "
     "decision stricter, never looser."],
], [0.45, 1.5, 3.05])
heading("Likely questions", 2)
table(["Question", "Answer"], [
    ["What if the AI model is wrong or manipulated?", "It can only make decisions stricter. Rules decide first; the "
     "model can add an escalation or a denial, never an approval. With the model switched off, the system still works."],
    ["Can the agent lie about what it is doing?", "No. The verb comes from the call itself: a DELETE statement is a "
     "delete, whatever the agent says."],
    ["Is the data real?", "Yes, a real seeded PostgreSQL database. Show the injected row with the command below."],
    ["How fast is it?", "Rule decisions take milliseconds; the model is consulted only when needed."],
    ["What about sub-agents?", "A sub-agent gets a narrower warrant; it can never have more authority than its parent."],
    ["Who can change the audit log?", "Nobody without detection: tampering is reported at the exact entry."],
], [1.6, 3.4])
code("""
docker compose -f deploy/docker-compose.yml exec postgres psql -U postgres -d acme \\
  -c "SELECT id, description FROM vendors WHERE description LIKE '%payment holds%';"
""")
heading("Plan B: no internet or the server is unreachable", 2)
p("The same demo runs on your laptop. Start <b>Docker Desktop</b>, wait until it says Running, open <b>Git Bash</b>:")
code("""
cd "/d/Crack - Google or  Die/Google-Buildathon/WARRANT"
export WARRANT_PEP_HOST_PORT=18080     # your laptop's port 8080 is used by another program (Apache)
./scripts/demo-up.sh
./scripts/demo-reset.sh && ./scripts/demo-run.sh --gate on --approve console
""")
p("Then use " + c("http://localhost:3000") + " in the browser (sign in as r.menon). Run "
  + c("./scripts/demo-up.sh") + " once tonight as well, so the laptop images are already built.", small)

# ---------------------------------------------------------------------------------------------------- part 10
heading("Part 10. Stop, restart and clean up")
table(["To…", "Run in Cloud Shell"], [
    ["Pause the server (keeps everything; link unchanged; compute charges stop)",
     c("gcloud compute instances stop warrant-demo --zone=asia-south1-a")],
    ["Start it again (services come back by themselves in about 3 minutes)",
     c("gcloud compute instances start warrant-demo --zone=asia-south1-a")],
    ["See the password again (on the server)", c("cat ~/WARRANT/.local/demo-password")],
    ["Delete everything after the hackathon", "Navigation menu (three-line icon) → " + click("IAM & Admin") + " → " + click("Settings") + " → "
     + click("SHUT DOWN") + " (deletes the whole project and stops all charges)."],
], [2.4, 2.6])
callout("note", "A stopped server still has a small charge for its disk and the reserved IP (a few cents per day). "
        "Check spending any time under Navigation menu → Billing → Reports.")

# ---------------------------------------------------------------------------------------------------- part 11
heading("Part 11. If something goes wrong")
table(["What you see", "What to do"], [
    ["Billing must be enabled / billing account required", "Part 2, last step: link the free-trial billing account to the project."],
    ["The resource ... networks/default was not found", "Run " + c("gcloud compute networks create default --subnet-mode=auto")
     + " and " + c("gcloud compute firewall-rules create default-allow-ssh --allow=tcp:22 --network=default")
     + ", then repeat Part 4.3 and 4.4."],
    ["Quota exceeded for CPUS", "Use " + c("--machine-type=e2-standard-2") + " (slower first build), or request a quota "
     "increase under IAM & Admin → Quotas."],
    ["gcloud compute ssh hangs or fails", "Wait one minute after creating the server and try again. Or use the "
     + click("SSH") + " button next to warrant-demo on the VM instances page; then type the same commands."],
    [c("permission denied ... docker.sock"), "You skipped the exit and reconnect in Part 6. Type " + c("exit")
     + ", reconnect, try again."],
    [c("./scripts/...: Permission denied"), "Run " + c("chmod +x scripts/*.sh scripts/warrant gradlew") + " inside ~/WARRANT."],
    ["cloud-demo-up.sh stops with an error during the build", "Run it again: it continues where it stopped. If it fails "
     "twice, run " + c("docker compose -f deploy/docker-compose.yml logs --tail 50") + " and look at the last lines."],
    ["Browser: certificate error", "Check " + c("getent hosts warrant.services") + " shows your server IP; wait 5 minutes "
     "and reload. Still failing: see the note at the end of Part 7."],
    ["warrant.services shows a parking or coming-soon page", "Old records or domain forwarding are still active at your "
     "registrar. Delete them (Part 4.5, step 3) and wait 10 to 30 minutes."],
    ["Works on your phone but not on your laptop", "Your laptop remembers the old address. Try another browser, or run "
     + c("ipconfig /flushdns") + " in Windows Command Prompt."],
    ["Cloudflare: too many redirects", "Set both records to <b>DNS only</b> (grey cloud), not Proxied."],
    ["Browser asks for the password again and again", "The username is exactly " + kbd("demo") + " (lower case)."],
    ["Console says the view could not load", "Services are still starting. Wait one minute, reload."],
    ["demo-run.sh --gate on prints demo expectations not met", "Run " + c("./scripts/demo-reset.sh") + " first, then "
     "run it again. Each run needs a fresh reset."],
    ["Everything is stuck after restarting the server", "On the server: " + c("cd ~/WARRANT && ./scripts/cloud-demo-up.sh")
     + " (fast the second time; the link and password stay the same)."],
], [1.9, 3.1])

# ---------------------------------------------------------------------------------------------------- part 12
heading("Part 12. After the hackathon: real projects and production")
p("The single server is right for a demonstration. For a company using Warrant with real agents and real data, deploy "
  "the production design described in <b>Warrant_GCP_Deployment_Guide.pdf</b> (guide v1):")
table(["Demo server (this guide)", "Production (guide v1)"], [
    ["Everything in Docker on one VM", "Gateway, control plane, classifier and console on Cloud Run, scaled automatically"],
    ["PostgreSQL and Redis in containers", "Cloud SQL (high availability, backups, login with Google identities, no "
     "password) and Memorystore with TLS"],
    ["Development signing keys on the server", "Cloud KMS hardware-protected keys per customer; private keys never leave KMS"],
    ["Demo sign-in behind one shared password", "Google sign-in for every person, with roles (approver, admin, auditor)"],
    ["warrant.services on one server", "console.warrant.services, api.warrant.services and pep.warrant.services "
     "behind Google's HTTPS load balancer and Cloud Armor (the demo keeps the main address)"],
    ["Demo ERP system", "Your real systems, whose credentials live only in Secret Manager"],
], [2.3, 2.7])
heading("How a real application uses Warrant", 2)
numbered([
    "<b>Register the system</b> the agent works on (a database, an API) as a tool, with its credential in Secret Manager. "
    "The agent never sees that credential.",
    "<b>Write the rules</b> in the policy editor: what is allowed, what needs a person, what is never allowed. Test them "
    "against recent real decisions before publishing.",
    "<b>When a person starts a task</b> in your app, your backend asks Warrant for a warrant on their behalf: their "
    "instruction, the allowed scope and the limits.",
    "<b>The agent makes every tool call through the Warrant gateway</b> with the Java SDK, the Python client, MCP, or "
    "plain HTTPS. Each call is allowed, denied with a reason, or sent to a person in real time.",
    "<b>Auditors</b> verify the tamper-evident record at any time, independently of Warrant.",
])
code("""
// Java agent, every call through Warrant
switch (warrant.call("sql.execute", Map.of("q", sql))) {
    case ToolResult.Allowed ok     -> use(ok.body());
    case ToolResult.Denied no      -> stop(no.reasonCode(), no.explanation());
    case ToolResult.Escalated wait -> warrant.await(wait.escalationId(), Duration.ofMinutes(5));
}
""")
callout("security", "Never put real company data or real credentials on the demo server. It uses development keys "
        "and a shared demo password. Delete the project after the hackathon (Part 10).")
p("Files in the project folder you may want to show: " + c("README.md") + " (overview), " + c("docs/adr/")
  + " (design decisions), " + c("deploy/terraform/") + " (production infrastructure as code), "
  + c("policies/examples/vendors.policy") + " (the demo policy).", small)


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
    canvas.drawCentredString(W / 2, H - 135 * mm, "Warrant Go-Live Guide")
    canvas.setFont("Sans", 12.5)
    canvas.setFillColor(colors.HexColor("#B0B0AA"))
    canvas.drawCentredString(W / 2, H - 146 * mm, "From a new Google Cloud account to https://warrant.services,")
    canvas.drawCentredString(W / 2, H - 153 * mm, "click by click, plus the presentation script")
    canvas.setStrokeColor(colors.HexColor("#3A3A36"))
    canvas.line(W / 2 - 40 * mm, H - 168 * mm, W / 2 + 40 * mm, H - 168 * mm)
    canvas.setFont("Sans", 9.5)
    canvas.drawCentredString(W / 2, H - 178 * mm, "Version 2.1  ·  21 November 2026  ·  for first-time Google Cloud users")
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
    canvas.drawString(MARGIN + 11 * mm, H - 11.6 * mm, "Warrant  ·  Go-Live Guide  ·  warrant.services")
    canvas.drawRightString(W - MARGIN, H - 11.6 * mm, "v2.1")
    canvas.setStrokeColor(LINE)
    canvas.line(MARGIN, H - 15 * mm, W - MARGIN, H - 15 * mm)
    canvas.drawRightString(W - MARGIN, 10 * mm, str(doc.page))
    canvas.drawString(MARGIN, 10 * mm, "Warrant — authorization for AI agents")
    canvas.restoreState()


doc = Guide(OUT, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=22 * mm, bottomMargin=18 * mm,
            title="Warrant Go-Live Guide v2", author="Warrant", subject="Deployment, production and integration guide")
frame = Frame(MARGIN, 18 * mm, CONTENT_W, H - 40 * mm, id="body", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
doc.addPageTemplates([PageTemplate(id="cover", frames=[frame], onPage=cover),
                      PageTemplate(id="body", frames=[frame], onPage=page)])
doc.multiBuild(story)
print("wrote", OUT)
