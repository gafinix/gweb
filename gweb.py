from flask import Flask, request, render_template_string
import requests
import socket
import ssl

app = Flask(__name__)

# HTML template for the web interface
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Website Safety Checker</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 700px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px 0px #888888; }
        h1 { color: #333333; }
        .result { margin-top: 20px; padding: 10px; background-color: #e7f3fe; border: 1px solid #b3d8ff; border-radius: 5px; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Website Safety Checker</h1>
        <form method="POST">
            <label for="url">Enter Website URL:</label><br><br>
            <input type="text" id="url" name="url" placeholder="example.com" required style="width: 100%; padding: 10px;">
            <br><br>
            <input type="submit" value="Check Website" style="padding: 10px 20px;">
        </form>
        {% if results %}
            <div class="result">
                <h2>Results for {{ url }}</h2>
                {% for result in results %}
                    <p>{{ result|safe }}</p>
                {% endfor %}
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

def check_ssl_cert(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return f"<span class='success'>SSL Certificate is valid for {cert['subject'][0][1]}</span>"
    except Exception as e:
        return f"<span class='error'>SSL error: {e}</span>"

def check_http_headers(url):
    try:
        response = requests.get(f"https://{url}", timeout=5)
        headers = response.headers
        security_headers = {
            "Strict-Transport-Security": "Helps enforce HTTPS connections.",
            "Content-Security-Policy": "Mitigates XSS attacks.",
            "X-Content-Type-Options": "Prevents MIME-type sniffing.",
            "X-Frame-Options": "Protects against clickjacking.",
            "X-XSS-Protection": "Provides basic XSS protection."
        }

        results = []
        for header, desc in security_headers.items():
            if header in headers:
                results.append(f"<span class='success'>{header}: Present ({desc})</span>")
            else:
                results.append(f"<span class='error'>{header}: Missing ({desc})</span>")
        return results
    except requests.exceptions.RequestException as e:
        return [f"<span class='error'>Request error: {e}</span>"]

@app.route("/", methods=["GET", "POST"])
def home():
    results = None
    if request.method == "POST":
        url = request.form["url"]
        results = [check_ssl_cert(url)]
        results.extend(check_http_headers(url))
        return render_template_string(HTML_TEMPLATE, url=url, results=results)
    return render_template_string(HTML_TEMPLATE, results=results)

if __name__ == "__main__":
    app.run(debug=True)
