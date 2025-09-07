import csv
from pathlib import Path
from datetime import datetime

SEVERITY_COLORS = {
    "INFO": "#d9edf7",
    "LOW": "#fcf8e3",
    "MEDIUM": "#f2dede",
    "HIGH": "#f2b0b0",
    "CRITICAL": "#d9534f"
}

def generate_csv_report(findings, filename="report.csv"):
    fields = ["S.No", "Title", "Severity", "OWASP", "NIST/CWE", "File", "Line", "Snippet"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for i, fnd in enumerate(findings,1):
            writer.writerow({
                "S.No": i,
                "Title": fnd.get("title"),
                "Severity": fnd.get("severity"),
                "OWASP": fnd.get("owasp"),
                "NIST/CWE": fnd.get("nist"),
                "File": fnd.get("file"),
                "Line": fnd.get("line"),
                "Snippet": fnd.get("snippet")
            })

def generate_html_report(findings, filename="report.html"):
    total_count = len(findings)
    severity_counts = {"INFO":0,"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}
    for f in findings:
        sev = f.get("severity","INFO")
        severity_counts[sev] = severity_counts.get(sev,0)+1

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Stratus Report</title>
<style>
body{{font-family:Arial;}}
table{{border-collapse: collapse;width:100%;}}
th,td{{border:1px solid #ddd;padding:8px;}}
th{{background-color:#f2f2f2;cursor:pointer;}}
tr:hover{{background-color:#f5f5f5;}}
pre{{white-space:pre-wrap;word-wrap:break-word;}}
</style>
<script>
function sortTable(n){{
  var table=document.getElementById("reportTable"),rows,i,x,y,shouldSwitch,dir,switchcount=0;
  dir="asc";
  for(i=1;i<table.rows.length;i++){{
    shouldSwitch=false;
    x=table.rows[i].getElementsByTagName("TD")[n];
    y=table.rows[i+1]?table.rows[i+1].getElementsByTagName("TD")[n]:null;
    if(!y) break;
    if(dir=="asc"){if(x.innerHTML.toLowerCase()>y.innerHTML.toLowerCase()){shouldSwitch=true;break;}}
    else{if(x.innerHTML.toLowerCase()<y.innerHTML.toLowerCase()){shouldSwitch=true;break;}}
  }}
  if(shouldSwitch){table.rows[i].parentNode.insertBefore(table.rows[i+1],table.rows[i]);switchcount++;} 
  else if(switchcount==0 && dir=="asc"){dir="desc";sortTable(n);}
}}
</script>
</head>
<body>
<h1>Stratus v5 Security Report</h1>
<p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<h3>Summary:</h3>
<ul>
<li>Total Findings: {total_count}</li>
<li>INFO: {severity_counts['INFO']}</li>
<li>LOW: {severity_counts['LOW']}</li>
<li>MEDIUM: {severity_counts['MEDIUM']}</li>
<li>HIGH: {severity_counts['HIGH']}</li>
<li>CRITICAL: {severity_counts['CRITICAL']}</li>
</ul>
<table id="reportTable">
<tr>
<th onclick="sortTable(0)">S.No</th>
<th onclick="sortTable(1)">Title</th>
<th onclick="sortTable(2)">Severity</th>
<th onclick="sortTable(3)">OWASP</th>
<th onclick="sortTable(4)">NIST/CWE</th>
<th onclick="sortTable(5)">File</th>
<th onclick="sortTable(6)">Line</th>
<th>Snippet</th>
</tr>"""

    for i, f in enumerate(findings,1):
        sev = f.get("severity","INFO")
        color = SEVERITY_COLORS.get(sev,"#fff")
        html += f"<tr style='background-color:{color}'>"
        html += f"<td>{i}</td>"
        html += f"<td>{f.get('title')}</td>"
        html += f"<td>{sev}</td>"
        html += f"<td>{f.get('owasp')}</td>"
        html += f"<td>{f.get('nist')}</td>"
        html += f"<td>{f.get('file')}</td>"
        html += f"<td>{f.get('line')}</td>"
        html += f"<td><pre>{f.get('snippet')}</pre></td>"
        html += "</tr>"
    html += "</table></body></html>"

    with open(filename,"w", encoding="utf-8") as f:
        f.write(html)
