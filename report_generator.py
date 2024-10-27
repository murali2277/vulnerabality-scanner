from jinja2 import Template

report_template = """
<!DOCTYPE html>
<html>
<head>
    <title>VAPT Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .container { max-width: 800px; margin: auto; padding: 20px; }
        h1 { text-align: center; }
        .result { margin-bottom: 20px; }
        .vulnerable { color: red; }
        .safe { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Assessment Report</h1>
        {% for result in results %}
        <div class="result">
            <h2>URL/File: {{ result.url }}</h2>
            <p>Vulnerability: {{ result.vulnerability }}</p>
            <p>Result: <strong class="{{ 'vulnerable' if 'Found' in result.result else 'safe' }}">{{ result.result }}</strong></p>
        </div>
        {% endfor %}
    </div>
</body>
</html>
"""

def generate_report(results):
    # Create HTML report
    template = Template(report_template)
    report_html = template.render(results=results)

    with open('templates/report.html', 'w') as file:
        file.write(report_html)

    print("Report generated: report.html")
