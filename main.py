from flask import Flask, request, render_template_string, jsonify
from datetime import datetime
import geoip2.database
import ipaddress
import requests
import json

app = Flask(__name__)

city_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
asn_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")

VPN_API_KEY = "YOUR_IPAPI_KEY"   # 👈 put your key here

def is_private(ip):
    return ipaddress.ip_address(ip).is_private

# -------------------- MAIN PAGE --------------------
@app.route("/")
def index():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    country = city = isp = "Private IP"
    lat = lon = None
    vpn = "Unknown"

    if not is_private(ip):
        try:
            city_res = city_reader.city(ip)
            asn_res = asn_reader.asn(ip)

            country = city_res.country.name or "Unknown"
            city = city_res.city.name or "Unknown"
            lat = city_res.location.latitude
            lon = city_res.location.longitude
            isp = asn_res.autonomous_system_organization
        except:
            pass

        # VPN Detection
        r = requests.get(f"https://api.ipapi.is/?q={ip}&key={VPN_API_KEY}")
        data = r.json()
        vpn = "Yes" if data.get("is_vpn") else "No"

    log = {
        "time": str(datetime.now()),
        "ip": ip,
        "country": country,
        "city": city,
        "isp": isp,
        "vpn": vpn
    }

    with open("access.log", "a") as f:
        f.write(json.dumps(log) + "\n")

    return render_template_string(PAGE, **log, lat=lat, lon=lon)

# -------------------- GPS --------------------
@app.route("/gps", methods=["POST"])
def gps():
    data = request.json
    lat = data["lat"]
    lon = data["lon"]

    r = requests.get(
        "https://nominatim.openstreetmap.org/reverse",
        params={"lat": lat, "lon": lon, "format": "json"},
        headers={"User-Agent": "CyberLab"}
    )

    return jsonify({
        "address": r.json().get("display_name", "Unknown"),
        "lat": lat,
        "lon": lon
    })

# -------------------- ADMIN DASHBOARD --------------------
@app.route("/admin")
def admin():
    logs = []
    try:
        with open("access.log") as f:
            logs = [json.loads(line) for line in f.readlines()]
    except:
        pass

    return render_template_string(ADMIN, logs=logs[::-1])

# -------------------- HTML --------------------
PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Cybersecurity Lab</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<style>#map{height:400px}</style>
</head>
<body>

<h2>Visitor Info</h2>
<p><b>IP:</b> {{ ip }}</p>
<p><b>Country:</b> {{ country }}</p>
<p><b>City:</b> {{ city }}</p>
<p><b>ISP:</b> {{ isp }}</p>
<p><b>VPN:</b> {{ vpn }}</p>

<h3>Map</h3>
<div id="map"></div>

<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script>
let map = L.map('map').setView([{{ lat or 0 }}, {{ lon or 0 }}], 5);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

{% if lat and lon %}
L.marker([{{ lat }}, {{ lon }}]).addTo(map)
 .bindPopup("IP-based location").openPopup();
{% endif %}

navigator.geolocation.getCurrentPosition(pos => {
 fetch("/gps", {
   method:"POST",
   headers:{"Content-Type":"application/json"},
   body:JSON.stringify({
     lat:pos.coords.latitude,
     lon:pos.coords.longitude
   })
 })
 .then(r=>r.json())
 .then(d=>{
   L.marker([d.lat,d.lon]).addTo(map)
     .bindPopup("GPS location").openPopup();
 });
});
</script>

<p><a href="/admin">Admin Dashboard</a></p>
</body>
</html>
"""

ADMIN = """
<h2>Admin Dashboard</h2>
<table border="1">
<tr>
<th>Time</th><th>IP</th><th>Country</th>
<th>City</th><th>ISP</th><th>VPN</th>
</tr>
{% for l in logs %}
<tr>
<td>{{ l.time }}</td>
<td>{{ l.ip }}</td>
<td>{{ l.country }}</td>
<td>{{ l.city }}</td>
<td>{{ l.isp }}</td>
<td>{{ l.vpn }}</td>
</tr>
{% endfor %}
</table>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
