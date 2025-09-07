# reports.py
import csv
from datetime import datetime

def generate_csv_report(findings, output_file):
    """
    Generate CSV report from findings
    :param findings: list of dicts with keys:
                     'sno','title','severity','owasp','nist','file','line','snippet'
    :param output_file: CSV filename
    """
    fieldnames = ['S.No', 'Title', 'Severity', 'OWASP', 'NIST/CWE', 'File', 'Line', 'Snippet']
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow({
                'S.No': f.get('sno', ''),
                'Title': f.get('title', ''),
                'Severity': f.get('severity', ''),
                'OWASP': f.get('owasp', ''),
                'NIST/CWE': f.get('nist', ''),
                'File': f.get('file', ''),
                'Line': f.get('line', ''),
                'Snippet': f.get('snippet', '')
            })

def generate_html_report(findings, output_file):
    """
    Generate sortable HTML report from findings
    :param findings: list of dicts with keys:
                     'sno','title','severity','owasp','nist','file','line','snippet'
    :param output_file: HTML filename
    """
    html_header = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Stratus Scan Report</title>
<style>
body {{ font-family: Arial, sans-serif; }}
table {{
  border-collapse: collapse;
  width: 100%;
}}
th, td {{
  border: 1px solid #dddddd;
  text-align: left;
  padding: 8px;
}}
th {{
  cursor: pointer;
  background-color: #f2f2f2;
}}
tr:nth-child(even) {{background-color: #f9f9f9;}}
.INFO {{ background-color: #d9edf7; }}
.LOW {{ background-color: #fcf8e3; }}
.MEDIUM {{ background-color: #f2dede; }}
.HIGH {{ background-color: #f2a3a3; }}
.CRITICAL {{ background-color: #d9534f; color: white; }}
</style>
<script>
function sortTable(n) {{
  var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
  table = document.getElementById("reportTable");
  switching = true;
  dir = "asc"; 
  while (switching) {{
    switching = false;
    rows = table.rows;
    for (i = 1; i < (rows.length - 1); i++) {{
      shouldSwitch = false;
      x = rows[i].getElementsByTagName("TD")[n];
      y = rows[i + 1].getElementsByTagName("TD")[n];
      if (dir == "asc") {{
        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {{
          shouldSwitch = true;
          break;
        }}
      }} else if (dir == "desc") {{
        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {{
          shouldSwitch = true;
          break;
        }}
      }}
    }}
    if (shouldSwitch) {{
      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
      switching = true;
      switchcount++;      
    }} else {{
      if (switchcount == 0 && dir == "asc") {{
        dir = "desc";
        switching = true;
      }}
    }}
  }}
}}
</script>
</head>
<body>
<h2>Stratus Scan Report</h2>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<table id="reportTable">
<tr>
  <th onclick="sortTable(0)">S.No</th>
  <th onclick="sortTable(1)">Title</th>
  <th onclick="sortTable(2)">Severity</th>
  <th onclick="sortTable(3)">OWASP</th>
  <th onclick="sortTable(4)">NIST/CWE</th>
  <th onclick="sortTable(5)">File</th>
  <th onclick="sortTable(6)">Line</th>
  <th onclick="sortTable(7)">Snippet</th>
</tr>
"""

    html_rows = ""
    for f in findings:
        severity_class = f.get('severity', 'INFO').upper()
        html_rows += f"""
<tr class="{severity_class}">
  <td>{f.get('sno', '')}</td>
  <td>{f.get('title', '')}</td>
  <td>{f.get('severity', '')}</td>
  <td>{f.get('owasp', '')}</td>
  <td>{f.get('nist', '')}</td>
  <td>{f.get('file', '')}</td>
  <td>{f.get('line', '')}</td>
  <td><pre>{f.get('snippet', '')}</pre></td>
</tr>
"""

    html_footer = """
</table>
</body>
</html>
"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_header + html_rows + html_footer)
