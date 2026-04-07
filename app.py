from flask import Flask, request, render_template_string
import requests
import ollama
from whois import whois
import shodan
from dotenv import load_dotenv
import os
from taxii2client.v20 import Server
import stix2
import socket
import re

load_dotenv()

app = Flask(__name__)

SHODAN_API = os.getenv("SHODAN_API_KEY")
VT_API = os.getenv("VT_API_KEY")
OTX_API = os.getenv("OTX_API_KEY")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mark's OSINT IOC Analyzer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }
        .container { width: 90%; max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; text-align: center; }
        form { text-align: center; margin: 20px 0; }
        input[type="text"] { width: 70%; max-width: 400px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 15px; border: none; background-color: #007BFF; color: white; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        pre { white-space: pre-wrap; word-wrap: break-word; background-color: #f9f9f9; padding: 15px; border: 1px solid #ddd; border-radius: 4px; }
        .debug { font-size: 12px; color: #555; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Mark's OSINT IOC Analyzer</h1>
        <form method="POST">
            <input type="text" name="query" placeholder="Enter IP or Domain" required />
            <button type="submit">Analyze</button>
        </form>
        {% if report %}
            <h2>Threat Report</h2>
            <pre>{{ report }}</pre>
        {% endif %}
        {% if debug_info %}
            <div class="debug">
                <h3>Debug Output (Raw Source Responses)</h3>
                <pre>{{ debug_info }}</pre>
            </div>
        {% endif %}
    </div>
</body>
</html>
'''

def get_shodan_data(target):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{target}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "success": True,
                "data": {
                    "ip": data.get("ip"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "tags": data.get("tags", [])
                }
            }
        elif r.status_code == 404:
            return {"success": False, "error": "No data found for this IP in Shodan InternetDB"}
        else:
            return {"success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}     
        
def get_virustotal_data(target):
    try:
        # Handle bytes object by decoding if necessary
        if isinstance(target, bytes):
            target = target.decode('utf-8').strip()
        
        headers = {"x-apikey": VT_API}
        
        # check if it's a valid IPv4 pattern
        parts = target.split('.')
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
            
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            malicious_engines = [k for k, v in results.items() if v.get("category") == "malicious"]   
            suspicious_engines = [k for k, v in results.items() if v.get("category") == "suspicious"]      
            phishing_engines = [k for k, v in results.items() if v.get("result") and "phish" in v["result"].lower()]
            return {
                "success": True,
                "data": {
                    "stats": stats,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "suspicious_engines": suspicious_engines,
                    "malicious_engines": malicious_engines,
                    "phishing_engines": phishing_engines,
                    "all_results": {k: v.get("result") for k, v in results.items() if v.get("result")}
                }
            }
        elif r.status_code == 404:
            return {"success": False, "error": "Not found in VirusTotal database"}
        else:
            return {"success": False, "error": f"VT API Error: {r.status_code} - {r.text}"}
    except Exception as e:
        return {"success": False, "error": str(e)}   

def get_whois_data(target):
    try:
        w = whois(target)
        return {
            "success": True,
            "data": {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "org": w.org,
                "country": w.country,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers,
                "emails": w.emails,
                "updated_date": w.updated_date
            }
        }
    except Exception as e:
        return {"success": False, "error": f"WHOIS: {str(e)}"}
        
def dns_lookup(target):
    try:
        if isinstance(target, bytes):
            target = target.decode('utf-8').strip()
        
        # Reverse DNS: IP → Hostname
        try:
            socket.inet_pton(socket.AF_INET, target)
            hostname, _, _ = socket.gethostbyaddr(target)
            return {
                "success": True,
                "type": "reverse",
                "target": target,
                "hostname": hostname,
                "ip": target
            }
        except socket.herror:
            return {"success": False, "error": f"No reverse DNS record for {target}"}
        except socket.error:
            pass  # Not an IP, try forward

        # Forward DNS: Domain → IPs
        try:
            ip_list = socket.gethostbyname_ex(target)
            return {
                "success": True,
                "type": "forward",
                "target": target,
                "hostname": ip_list[0],
                "ips": ip_list[2]
            }
        except socket.gaierror:
            return {"success": False, "error": f"Could not resolve domain {target}"}

    except Exception as e:
        return {"success": False, "error": str(e)}   
 

def indicator_in_list(target, url, name):
    try:
        r = requests.get(url, timeout=5)
        if target in r.text:
            return {"success": True, "reason": f"Listed in {name}"}
        return {"success": False}
    except Exception as e:
        return {"success": False, "error": f"{name} request failed: {str(e)}"}

def get_abusech_status(target):
    feodo = indicator_in_list(target, "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", "abuse.ch Feodo Tracker")
    ssl = indicator_in_list(target, "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", "abuse.ch SSL Blacklist")
    return feodo if feodo["success"] else ssl if ssl["success"] else {"success": False}

def get_emerging_threats_status(target):
    return indicator_in_list(target, "http://rules.emergingthreats.net/blockrules/compromised-ips.txt", "Emerging Threats")

def get_spamhaus_status(target):
    return indicator_in_list(target, "https://www.spamhaus.org/drop/drop.txt", "Spamhaus DROP")

def get_tor_exit_nodes_status(target):
    return indicator_in_list(target, "https://check.torproject.org/torbulkexitlist", "Tor Exit Node")


def get_alienvault_otx_data(target):
    # Detect if the target is an IPv4 address using regex
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", target):
        # It's an IP address
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"
    else:
        # Assume it's a domain
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"
    
    try:
        headers = {"X-OTX-API-KEY": OTX_API}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "success": True,
                "data": {
                    "pulses": data.get("pulse_info", {}).get("count", 0),
                    "malware": data.get("malware", {}).get("count", 0)
                }
            }
        elif r.status_code == 404:
            return {"success": False, "error": "Not found in OTX"}
        else:
            return {"success": False, "error": f"OTX API {r.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

          

def get_misp_data():
    try:
        # Example public MISP feed (CIRCL)
        r = requests.get("https://www.circl.lu/doc/misp/feed-osint.json")
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def get_firehol_data():
    try:
        r = requests.get("https://iplists.firehol.org/files/firehol_level1.netset")
        return r.text.splitlines()
    except Exception as e:
        return {"error": str(e)}


def get_threatfox_data(target):
    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": target}
        headers = {"Auth-Key": os.getenv("THREATFOX_API_KEY")}
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "ok":
                return {
                    "success": True,
                    "data": data["data"][0] if data["data"] else {}
                }
        return {"success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}   

def get_urlhaus_data(target):
    try:
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        data = {"host": target}
        headers = {"Auth-Key": os.getenv("URLHAUS_API_KEY")}
        r = requests.post(url, data=data, headers=headers, timeout=10)
        if r.status_code == 200:
            resp = r.json()
            if resp.get("query_status") in ["ok", "no_results"]:
                return {
                    "success": True,
                    "data": resp
                }
        return {"success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}   

def get_greynoise_data(target):
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{target}", headers={"key": "GREYNOISE_API_KEY", "accept": "application/json"}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "success": True,
                "data": {
                    "noise": data.get("noise"),
                    "classification": data.get("classification"),
                    "name": data.get("name"),
                    "cve": data.get("cve")
                }
            }
        return {"success": False, "error": f"GreyNoise: {r.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}   
        
    
        
@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    debug_info = ""
    if request.method == "POST":
        query = request.form["query"].strip()
        if not query:
            return render_template_string(HTML_TEMPLATE, report="Invalid input.")

        # Fetch data
        shodan = get_shodan_data(query)
        vt = get_virustotal_data(query)
        whois_data = get_whois_data(query)
        dns_data = dns_lookup(query)
        dns_result = dns_lookup(query)
        abusech = get_abusech_status(query)
        et = get_emerging_threats_status(query)
        spamhaus = get_spamhaus_status(query)
        tor = get_tor_exit_nodes_status(query)
        otx_data = get_alienvault_otx_data(query)
        firehol_data = get_firehol_data()
        misp_data = get_misp_data()
        threatfox_data = get_threatfox_data(query)
        urlhaus_data = get_urlhaus_data(query)
        greynoise_data = get_greynoise_data(query)           

        # Build debug output
        debug_info = f"""
Shodan: {'OK' if shodan['success'] else 'ERROR'} - {shodan.get('data', shodan.get('error'))}
VirusTotal: {'OK' if vt['success'] else 'ERROR'} - {vt.get('data', vt.get('error'))}
WHOIS: {'OK' if whois_data['success'] else 'ERROR'} - {whois_data.get('data', whois_data.get('error'))}
"AlienVault OTX: {'OK' if otx_data['success'] else 'ERROR'} - {otx_data.get('data', otx_data.get('error'))}"   
abuse.ch: {'OK' if abusech['success'] else 'NOT LISTED'} - {abusech.get('reason', 'No error')}
Emerging Threats: {'OK' if et['success'] else 'NOT LISTED'} - {et.get('reason', 'No error')}
"ThreatFox: {'OK' if threatfox_data['success'] else 'ERROR'} - {threatfox_data.get('data', threatfox_data.get('error'))}"
"URLhaus: {'OK' if urlhaus_data['success'] else 'ERROR'} - {urlhaus_data.get('data', urlhaus_data.get('error'))}"
DNS: {'OK' if dns_data['success'] else 'ERROR'} - {dns_data.get('data', dns_data.get('error'))}
"GreyNoise: {'OK' if greynoise_data['success'] else 'ERROR'} - {greynoise_data.get('data', greynoise_data.get('error'))}"   
Spamhaus: {'OK' if spamhaus['success'] else 'NOT LISTED'} - {spamhaus.get('reason', 'No error')}
Tor: {'OK' if tor['success'] else 'NOT LISTED'} - {tor.get('reason', 'No error')}
        """.strip()

        # Build findings
        findings = []
        threat_level = "Low"

        if shodan['success'] and shodan['data'].get('vulns'):
            findings.append(f"Shodan: Exposed vulnerabilities: {', '.join(shodan['data']['vulns'][:3])}")
            threat_level = "High"
            
        if vt['success']:
            vtd = vt['data']
            if vtd['malicious'] > 0:
                findings.append(f"VirusTotal: {vtd['malicious']} engines flagged as malicious ({', '.join(vtd['malicious_engines'][:3])})")
                threat_level = "High"
            if vtd['phishing_engines']:
                findings.append(f"VirusTotal: Phishing detected by {len(vtd['phishing_engines'])} engines ({', '.join(vtd['phishing_engines'][:3])})")
                threat_level = "High"
            if threat_level != "High" and (vtd['suspicious'] > 0 or vtd['suspicious_engines']):
                findings.append(f"VirusTotal: {vtd['suspicious']} engines flagged as suspicious ({', '.join(vtd['suspicious_engines'][:3])})")
                threat_level = "Medium"
            if threat_level == "Low" and vtd['malicious'] == 0 and not vtd['phishing_engines'] and vtd['suspicious'] == 0 and not vtd['suspicious_engines']:
                threat_level = "Low"
        
        if dns_result["success"]:
            if dns_result["type"] == "reverse":
                findings.append(f"DNS Reverse Lookup: {dns_result['ip']} → {dns_result['hostname']}")
            elif dns_result["type"] == "forward":
                findings.append(f"DNS Forward Lookup: {dns_result['target']} → {', '.join(dns_result['ips'])}")
            else:
                findings.append(f"DNS Lookup Failed: {dns_result['error']}")
                        
        if abusech['success']:
            findings.append(f"abuse.ch: {abusech['reason']}")
            if threat_level == "Low": threat_level = "Medium"
        if et['success']:
            findings.append(f"Emerging Threats: {et['reason']}")
            if threat_level == "Low": threat_level = "Medium"
        if spamhaus['success']:
            findings.append(f"Spamhaus: {spamhaus['reason']}")
            if threat_level == "Low": threat_level = "Medium"
        if tor['success']:
            findings.append(f"Tor: {tor['reason']}")
            if threat_level == "Low": threat_level = "Medium"
        if whois_data['success']:
            w = whois_data['data']
            if w.get('org'): findings.append(f"WHOIS: Registered to {w['org']}")
            if w.get('country'): findings.append(f"WHOIS: Country {w['country']}")
            if w.get('registrar'): findings.append(f"WHOIS: Registrar {w['registrar']}")
            
        if threatfox_data['success']:
            findings.append(f"ThreatFox: {threatfox_data['data']['threat_type']} ({threatfox_data['data']['malware']})")
        if urlhaus_data['success'] and 'url_count' in urlhaus_data['data']:
            findings.append(f"URLhaus: Listed with {urlhaus_data['data']['url_count']} malicious URLs")   
        if greynoise_data['success'] and greynoise_data['data']['classification'] != "benign":
            findings.append(f"GreyNoise: {greynoise_data['data']['classification']} ({greynoise_data['data']['name']})")   

        if not findings:
            findings = ["No threat indicators found across all sources."]
        
        context = (
            f"Shodan: {str(get_shodan_data)[:1500]} | "
            f"VirusTotal: {str(get_virustotal_data)[:1500]} | "
            f"AlienVault OTX: {str(otx_data)[:1500]} | "
            f"abuse.ch: {str(get_abusech_status)[:1500]} | "
            f"FireHOL: {str(get_firehol_data)[:1500]} | "
            f"Threatfox: {str(get_threatfox_data)[:1500]} | "
            f"URLhaus: {str(get_urlhaus_data)[:1500]} | "
            f"Greynoise: {str(get_greynoise_data)[:1500]} | "
            f"DNS: {str(dns_lookup)[:1500]} | "
            f"MISP: {str(get_misp_data)[:1500]}"
        )
        
        # Generate report
        prompt = f"""
        As a cybersecurity analyst, generate a concise threat report on the inputted query in plain English.
        Data: {context}
        Threat Level: {threat_level}
        Key Findings: {', '.join(findings[:6])}
        Include: ISP, geolocation, WHOIS, a summary of the data in {context} and recommended actions, all available DNS data, threat level, key findings from all sources, build the report as if talking to a technical team manager.
        Keep under 500 words.
        """
        try:
            response = ollama.generate(model="qwen3:8b", prompt=prompt)
            report = response['response']
        except Exception as e:
            report = f"Error generating report: {str(e)}"

    return render_template_string(HTML_TEMPLATE, report=report, debug_info=debug_info)

if __name__ == "__main__":
    app.run(debug=True)   