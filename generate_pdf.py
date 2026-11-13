import sys
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#718096"))
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 36, page_text)
        self.drawString(54, 36, "LightSIEM Prototype Presentation Guide — Confidential / Academic Use")
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 48, letter[0] - 54, 48)
        self.restoreState()

def build_pdf(filename):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#1A365D'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#4A5568'),
        spaceAfter=14
    )
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E3A8A'),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#2B6CB0'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#2D3748'),
        spaceAfter=5
    )
    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=body_style,
        leftIndent=14,
        firstLineIndent=-10,
        spaceAfter=3
    )
    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#1A202C'),
        backColor=colors.HexColor('#EDF2F7'),
        borderColor=colors.HexColor('#CBD5E0'),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )
    callout_style = ParagraphStyle(
        'Callout_Custom',
        parent=body_style,
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#2C5282'),
        backColor=colors.HexColor('#EBF8FF'),
        borderColor=colors.HexColor('#BEE3F8'),
        borderWidth=1,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("LightSIEM: AI/ML Cyber Threat Detection", title_style))
    story.append(Paragraph("<b>Comprehensive Prototype Walkthrough & Presentation Guide</b><br/>Dataset: Russell Mitchell (AECID/AIT) &bull; Architecture: Hybrid Rules + Isolation Forest & Random Forest", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2B6CB0'), spaceBefore=0, spaceAfter=10))

    # SECTION 1
    story.append(Paragraph("1. Project Architecture & Overview", h1_style))
    story.append(Paragraph("<b>LightSIEM</b> is a lightweight Security Information and Event Management system engineered in Python. Unlike enterprise tools (Splunk, Elastic) that demand gigabytes of memory and dedicated JVM services, LightSIEM runs with sub-60 MB RAM using standard library SQLite with FTS5 full-text indexing, achieving <b>60,000+ events/sec</b> ingestion throughput.", body_style))
    story.append(Paragraph("The system operates in 5 clean stages: <b>Collect &rarr; Parse/Normalize &rarr; Store &rarr; Detect (Hybrid Rules + AI/ML) &rarr; Visual Analytics & Web Dashboard</b>.", body_style))

    # SECTION 2
    story.append(Paragraph("2. Dataset Context: Russell Mitchell (AECID/AIT)", h1_style))
    story.append(Paragraph("The evaluation uses the <b>Russell Mitchell Cyber Attack Dataset</b> recorded by the Austrian Institute of Technology (AIT). Spanning 18 virtual hosts (~15 GB raw), the scenario simulates a full cyber-kill-chain attack.", body_style))
    story.append(Paragraph("<b>Target Host Selected: <code>intranet_server</code></b>", h2_style))
    story.append(Paragraph("For live demonstration, we focus on the primary victim host (<code>intranet_server</code>) containing <b>12,672 events</b>. This host contains the actual attack payloads:", body_style))
    story.append(Paragraph("&bull; <b><code>apache2/access.log</code>:</b> Web directory brute-force and vulnerability scans.", bullet_style))
    story.append(Paragraph("&bull; <b><code>auth.log</code>:</b> SSH authentication attempts and privilege escalation.", bullet_style))
    story.append(Paragraph("&bull; <b><code>openvpn.log</code> & <code>dnsmasq.log</code>:</b> Encrypted tunneling and internal DNS lookups.", bullet_style))
    story.append(Paragraph("&bull; <b>Ground Truth Attacker IP:</b> <code>172.19.131.174</code> (labeled in <code>labels/intranet_server/logs/</code>).", bullet_style))

    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#E2E8F0'), spaceBefore=8, spaceAfter=8))

    # SECTION 3
    story.append(Paragraph("3. Step-by-Step Prototype Demonstration Guide", h1_style))

    # Step 1
    story.append(Paragraph("<b>Step 1: Execute Model Ingestion & 4 Key AIML Charts</b>", h2_style))
    story.append(Paragraph("In VSCode terminal, run:", body_style))
    story.append(Paragraph("python3 demo_visualize.py /home/faang/Documents/LightSIEM_prototype/russellmitchell --host intranet_server --db rm_local.db", code_style))
    story.append(Paragraph("<i>(Shortcut if already cached: <code>python3 demo_visualize.py --skip-ingest</code>)</i>", body_style))
    story.append(Paragraph("<b>What happens under the hood:</b>", body_style))
    story.append(Paragraph("1. <b>Directory Walking:</b> Crawls <code>gather/intranet_server/logs/</code>, sorting rotated files chronologically.<br/>"
                           "2. <b>Normalization:</b> Regex transforms raw strings into unified JSON dicts with Unix timestamps.<br/>"
                           "3. <b>Feature Engineering:</b> Partitions traffic into 5-minute windows per IP, computing 8 behavioral features.<br/>"
                           "4. <b>Model Training:</b> Trains Isolation Forest (unsupervised) and Random Forest (100 trees, supervised) live in memory.<br/>"
                           "5. <b>Visual Rendering:</b> Renders 4 core evaluation charts sequentially.", body_style))

    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Step 2: Launch Real-Time Operations Web Dashboard</b>", h2_style))
    story.append(Paragraph("In VSCode terminal, run:", body_style))
    story.append(Paragraph("python3 lightsiem.py serve --db rm_local.db --port 8080", code_style))
    story.append(Paragraph("Open browser at <b>http://localhost:8080</b> to show the interactive web operations center:", body_style))
    story.append(Paragraph("&bull; <b>Event Timeline Graph:</b> Live bucketed event frequencies.<br/>"
                           "&bull; <b>Detected Alerts Table:</b> Real-time detections (SSH brute force, web scanning).<br/>"
                           "&bull; <b>Interactive Investigation:</b> Click attacker IP <code>172.19.131.174</code> to filter the entire log stream.<br/>"
                           "&bull; <b>FTS5 Full-Text Search:</b> Instant keyword search (e.g., '404' or 'root') over message bodies.", body_style))

    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Step 3: Run Quantitative Accuracy Benchmark</b>", h2_style))
    story.append(Paragraph("In a second VSCode terminal tab, run:", body_style))
    story.append(Paragraph("python3 lightsiem.py russell evaluate /home/faang/Documents/LightSIEM_prototype/russellmitchell --db rm_local.db", code_style))
    story.append(Paragraph("<b>Output Verification:</b> Generates quantitative scorecard cross-referencing alerts against ground truth. Shows <b>100% Parse Coverage</b> and <b>Precision: 1.0, Recall: 1.0, F1: 1.0</b> on attacker IP attribution.", body_style))

    story.append(PageBreak())

    # SECTION 4
    story.append(Paragraph("4. The 4 Key AIML Charts Explained in Depth", h1_style))

    table_data = [
        [Paragraph("<b>Chart</b>", h2_style), Paragraph("<b>Visual Elements</b>", h2_style), Paragraph("<b>Key Talking Point for Evaluators</b>", h2_style)],
        [
            Paragraph("<b>Chart 1:<br/>Event Timeline & Alerts</b>", body_style),
            Paragraph("&bull; Blue area: Events per 5 min<br/>&bull; Red dashed lines: Rule & ML alert triggers", body_style),
            Paragraph("<i>'Demonstrates temporal threat correlation. Shows background traffic volume and highlights the exact burst windows where brute-force and scanner alerts occurred.'</i>", body_style)
        ],
        [
            Paragraph("<b>Chart 2:<br/>Random Forest Feature Importance</b>", body_style),
            Paragraph("&bull; Horizontal ranked bars<br/>&bull; Features: err4xx_ratio, distinct_url_ratio, ssh_fail, etc.", body_style),
            Paragraph("<i>'Provides Explainable AI (XAI). Shows that HTTP 4xx error ratios and distinct URL counts have the highest Gini importance in identifying reconnaissance scanners.'</i>", body_style)
        ],
        [
            Paragraph("<b>Chart 3:<br/>Confusion Matrix Heatmap</b>", body_style),
            Paragraph("&bull; 2x2 Seaborn Heatmap<br/>&bull; Normal vs Attack windows<br/>&bull; TP, FP, TN, FN counts", body_style),
            Paragraph("<i>'Standard classification evaluation metric. Proves high True Positives on attack traffic windows with zero False Alarms on normal operational traffic.'</i>", body_style)
        ],
        [
            Paragraph("<b>Chart 4:<br/>ROC & AUC Comparison</b>", body_style),
            Paragraph("&bull; Isolation Forest (Orange)<br/>&bull; Random Forest (Green)<br/>&bull; Grey diagonal baseline", body_style),
            Paragraph("<i>'Directly benchmarks unsupervised anomaly detection vs. supervised classification. Both models exceed 0.95 AUC, confirming strong discriminatory power.'</i>", body_style)
        ],
    ]

    t = Table(table_data, colWidths=[120, 150, 234])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#EDF2F7')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E0')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t)

    story.append(Spacer(1, 10))

    # SECTION 5: TEAM ROLES
    story.append(Paragraph("5. Team Member Roles & Individual Speaking Scripts", h1_style))

    # Hemanth
    story.append(Paragraph("<b>Hemanth — Data Collection & Preprocessing Engineer</b>", h2_style))
    story.append(Paragraph("<b>Code Files:</b> <code>siem/russell.py</code>, <code>siem/parser.py</code>", body_style))
    story.append(Paragraph("<b>Speech Script:</b> <i>'I built the data collection and cleaning pipeline. I worked with the Russell Mitchell cyber attack dataset, mapping its multi-server hierarchy and writing regex parsers to normalize 5 distinct log formats (SSH, Apache, OpenVPN, DNS, Syslog) into standardized Unix epoch timestamps and structured event schemas. I also built the host/type filtering to isolate the victim server from the 15 GB raw archive.'</i>", callout_style))

    # Vivek
    story.append(Paragraph("<b>Vivek — Machine Learning & Detection Engine Engineer</b>", h2_style))
    story.append(Paragraph("<b>Code Files:</b> <code>siem/detect.py</code>, <code>siem/ml.py</code>, <code>evaluate_russell.py</code>", body_style))
    story.append(Paragraph("<b>Speech Script:</b> <i>'I engineered the threat detection and ML layers. I designed sliding-window streaming rules for instant detection of brute-force and web scans, plus two AI models: an Isolation Forest for unsupervised anomaly detection and a Random Forest trained on 8 behavioral features. I also implemented evasion-aware training to catch stealthy scanners that throttle request rates.'</i>", callout_style))

    # Abhishek
    story.append(Paragraph("<b>Abhishek — Storage Architecture, Web Dashboard & Visual Analytics</b>", h2_style))
    story.append(Paragraph("<b>Code Files:</b> <code>siem/store.py</code>, <code>siem/server.py</code>, <code>demo_visualize.py</code>, <code>lightsiem.py</code>", body_style))
    story.append(Paragraph("<b>Speech Script:</b> <i>'I designed the system architecture, database, and visual analytics. I built the SQLite storage layer with WAL mode and FTS5 full-text indexing, achieving over 60,000 events/second throughput. I developed the real-time browser dashboard at localhost:8080 and engineered the 4-chart visualization suite in demo_visualize.py to showcase our model metrics.'</i>", callout_style))

    story.append(Spacer(1, 6))

    # SECTION 6: FAQ
    story.append(Paragraph("6. High-Probability Evaluator Q&A", h1_style))
    story.append(Paragraph("<b>Q: Why use SQLite instead of Elasticsearch or MongoDB?</b><br/>"
                           "<b>A:</b> Elasticsearch requires multiple gigabytes of JVM memory. LightSIEM is designed for embedded edge environments: pure Python standard library, &lt;60 MB RAM, and SQLite FTS5 yields sub-millisecond search times without service overhead.", body_style))
    story.append(Paragraph("<b>Q: Why do you need both Rules and Machine Learning?</b><br/>"
                           "<b>A:</b> Rules catch obvious attacks instantaneously with zero latency. Machine learning (Isolation Forest & Random Forest) evaluates 5-minute behavioral windows, catching subtle, slow-and-low anomalies that evade fixed thresholds.", body_style))
    story.append(Paragraph("<b>Q: How did you validate accuracy?</b><br/>"
                           "<b>A:</b> The Russell Mitchell dataset includes JSONL label files marking exact attack lines. By correlating our alerted IPs against ground truth, we mathematically verified 1.0 Precision and 1.0 Recall on the victim server.", body_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF successfully built: {filename}")

if __name__ == "__main__":
    out_pdf = "/home/faang/Documents/LightSIEM_prototype/LightSIEM_Presentation_Guide.pdf"
    build_pdf(out_pdf)
