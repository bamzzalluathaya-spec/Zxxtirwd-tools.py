#!/usr/bin/env python3
# zxxtirwd_v2.py
# ZXXTIRWD TOOLS v2
# Terminal theme neon green on black
# White-hat OSINT utilities: YouTube / TikTok / Instagram / WhatsApp info / Email check / IP tracker / Device info
# Legal notice: This tool performs public checks only. It cannot retrieve passwords, device lists, precise WA location, or live "online" status without consent.

import os
import sys
import re
import json
import time
import socket
import platform
from pathlib import Path

# Optional libs
try:
    import requests
except Exception:
    requests = None

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
except Exception:
    phonenumbers = None

try:
    import dns.resolver
except Exception:
    dns = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import whois
except Exception:
    whois = None

try:
    import qrcode
    from PIL import Image
except Exception:
    qrcode = None

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ----------------------------
# CONFIG - optional API keys
# ----------------------------
CONFIG = {
    "YOUTUBE_API_KEY": os.getenv("YOUTUBE_API_KEY", "").strip(),
    "TWILIO_ACCOUNT_SID": os.getenv("TWILIO_ACCOUNT_SID", "").strip(),
    "TWILIO_AUTH_TOKEN": os.getenv("TWILIO_AUTH_TOKEN", "").strip(),
    "HIBP_API_KEY": os.getenv("HIBP_API_KEY", "").strip(),
    "IPINFO_TOKEN": os.getenv("IPINFO_TOKEN", "").strip(),
    "USER_AGENT": "Mozilla/5.0 (ZXXTIRWD/v2)"
}

OUTDIR = Path("results")
OUTDIR.mkdir(exist_ok=True)

# Colors
G = "\033[1;32m"
W = "\033[1;37m"
Y = "\033[1;33m"
R = "\033[1;31m"
END = "\033[0m"

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def logo():
    # Compact logo that fits phone screens
    print(G + r"""
           xxxxxxx+;        
       ;xXXXXXXXXXXXXXx;     
     +xXXXXXXXXXXXXXXXXXX+;  
   +xXx+XXXXXXXXXXXXXXX+xxx+ 
  ++x++xXXXXXXXx+XXXXXXx++x++
  +x+xxXXXXXXXX+XXXXXXXXx++x+
  +x+xXXXXXXXXXxXXXXXXXXXx+x+
  +x+xXXXXx+;+X+X+;+xXXXXx+x+
  ;xx+xXXX+;;;x;x;;;+XXXx++x+
  ++x++xXX;;;;;;;;;;;XXx++xx+
   ++x++xx;;;;;;;;;;;+x++x++ 
    ++x+++;;;;;;;;;+;+;+x++  
       ;xx++;;;;;;;++xx;     
          ;;;;;;;;;;;
    ..... .. ..  .... .. ..
    ...   .. .. ::    ...
    ..     ...   :::: .. ::
 
 
 MULTI TOOLS FOR HACKING BY ZXXTIRWD
""" + END)

def wait():
    try:
        input(G + "\n[ ENTER ]" + END)
    except Exception:
        pass

def save_json(label, data):
    fn = OUTDIR / f"{label}_report.json"
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return str(fn)

# ----------------------------
# Utilities
# ----------------------------
def shortnum(s):
    try:
        s = str(s)
        return int(s.replace(",",""))
    except Exception:
        return s

def parse_shorthand(s):
    try:
        s = str(s).strip().upper().replace(",","")
        if s.endswith("K"):
            return int(float(s[:-1]) * 1000)
        if s.endswith("M"):
            return int(float(s[:-1]) * 1000000)
        return int(float(s))
    except Exception:
        return s

# ----------------------------
# YouTube checker
# ----------------------------
def youtube_check(input_id):
    out = {"platform":"youtube", "input": input_id}
    if not requests:
        out["error"] = "requests missing"
        return out
    key = CONFIG.get("YOUTUBE_API_KEY","")
    headers = {"User-Agent": CONFIG["USER_AGENT"]}
    if key:
        # Try username first
        try:
            url = f"https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&forUsername={input_id}&key={key}"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                j = r.json()
                if j.get("items"):
                    it = j["items"][0]
                    out.update({
                        "title": it["snippet"].get("title"),
                        "subs": it["statistics"].get("subscriberCount"),
                        "videos": it["statistics"].get("videoCount"),
                        "views": it["statistics"].get("viewCount"),
                        "source": "youtube_api_username"
                    })
                    return out
            # Try id
            url2 = f"https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&id={input_id}&key={key}"
            r2 = requests.get(url2, headers=headers, timeout=10)
            if r2.status_code == 200:
                j2 = r2.json()
                if j2.get("items"):
                    it = j2["items"][0]
                    out.update({
                        "title": it["snippet"].get("title"),
                        "subs": it["statistics"].get("subscriberCount"),
                        "videos": it["statistics"].get("videoCount"),
                        "views": it["statistics"].get("viewCount"),
                        "source": "youtube_api_id"
                    })
                    return out
        except Exception as e:
            out["api_error"] = str(e)
    # fallback scraping
    tried = [
        f"https://www.youtube.com/{input_id}",
        f"https://www.youtube.com/c/{input_id}",
        f"https://www.youtube.com/user/{input_id}",
        f"https://www.youtube.com/channel/{input_id}"
    ]
    for u in tried:
        try:
            r = requests.get(u, headers=headers, timeout=10)
            if r.status_code == 200:
                m = re.search(r'\"subscriberCountText\".*?\"simpleText\":\"([^\"]+)\"', r.text)
                if m:
                    out["subs"] = m.group(1)
                # attempt title
                mm = re.search(r'<meta name="title" content="([^"]+)"', r.text)
                if mm:
                    out["title"] = mm.group(1)
                out["url_tried"] = u
                out["source"] = "scrape"
                return out
        except Exception:
            continue
    out["note"] = "No reliable data. Add YOUTUBE_API_KEY in CONFIG for best results"
    return out

# ----------------------------
# TikTok checker (best-effort)
# ----------------------------
def tiktok_check(username):
    out = {"platform":"tiktok", "username": username}
    if not requests:
        out["error"] = "requests missing"
        return out
    headers = {"User-Agent": CONFIG["USER_AGENT"]}
    # try public livecounts
    try:
        r = requests.get(f"https://tiktok.livecounts.io/user/{username}", headers=headers, timeout=10)
        if r.status_code == 200:
            j = r.json()
            user = j.get("user", {})
            out["followers"] = user.get("followerCount")
            out["likes"] = user.get("heartCount")
            out["nickname"] = user.get("nickname")
            out["source"] = "livecounts"
            return out
    except Exception:
        pass
    # fallback scrape
    try:
        url = f"https://www.tiktok.com/@{username}"
        r = requests.get(url, headers=headers, timeout=12)
        html = r.text
        m1 = re.search(r'"followerCount":\s*([0-9]+)', html)
        m2 = re.search(r'"heartCount":\s*([0-9]+)', html)
        if m1: out["followers"] = int(m1.group(1))
        if m2: out["likes"] = int(m2.group(1))
        meta = re.search(r'<meta name="description" content="([^"]+)"', html)
        if meta:
            out["meta"] = meta.group(1)
        out["source"] = "scrape"
        return out
    except Exception as e:
        out["error"] = str(e)
    return out

# ----------------------------
# Instagram checker (best-effort)
# ----------------------------
def instagram_check(username):
    out = {"platform":"instagram", "username":username}
    if not requests:
        out["error"] = "requests missing"
        return out
    headers = {"User-Agent": CONFIG["USER_AGENT"]}
    # try JSON endpoint
    try:
        url = f"https://www.instagram.com/{username}/?__a=1&__d=dis"
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            try:
                j = r.json()
                user = j.get("graphql", {}).get("user", {})
                out["followers"] = user.get("edge_followed_by", {}).get("count")
                out["posts"] = user.get("edge_owner_to_timeline_media", {}).get("count")
                out["full_name"] = user.get("full_name")
                out["bio"] = user.get("biography")
                out["source"] = "json_endpoint"
                return out
            except Exception:
                pass
    except Exception:
        pass
    # fallback scrape
    try:
        r2 = requests.get(f"https://www.instagram.com/{username}/", headers=headers, timeout=10)
        html = r2.text
        m = re.search(r'\"edge_followed_by\":\s*\{\"count\":\s*([0-9]+)\}', html)
        if m:
            out["followers"] = int(m.group(1))
            out["source"] = "scrape"
        else:
            meta = re.search(r'<meta name="description" content="([^"]+)"', html)
            if meta:
                out["meta"] = meta.group(1)
        return out
    except Exception as e:
        out["error"] = str(e)
    return out

# ----------------------------
# WhatsApp info (legal / non-intrusive)
# ----------------------------
def whatsapp_info(number):
    out = {"input": number}
    if not phonenumbers:
        out["error"] = "phonenumbers missing"
        return out
    try:
        p = phonenumbers.parse(number, None)
    except Exception as e:
        out["error"] = f"parse_error {e}"
        return out
    e164 = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    cc = phonenumbers.region_code_for_number(p)
    prov = None
    try:
        prov = carrier.name_for_number(p, "en")
    except Exception:
        prov = None
    tzs = []
    try:
        tzs = list(timezone.time_zones_for_number(p))
    except Exception:
        tzs = []
    out.update({
        "e164": e164,
        "international": intl,
        "country_code": cc,
        "carrier_guess": prov,
        "timezones": tzs,
        "is_valid": phonenumbers.is_valid_number(p),
        "is_possible": phonenumbers.is_possible_number(p)
    })
    # wa.me heuristic (reachable or not)
    if requests:
        try:
            no = re.sub(r'^\+', '', e164)
            wa = f"https://wa.me/{no}"
            r = requests.get(wa, headers={"User-Agent": CONFIG["USER_AGENT"]}, timeout=8, allow_redirects=True)
            out["wa_me_status"] = getattr(r, "status_code", None)
            out["wa_me_final"] = getattr(r, "url", None)
            # Note: reachable wa.me is a heuristic only; it does not prove online presence or identity
        except Exception as e:
            out["wa_me_error"] = str(e)
    else:
        out["wa_me_note"] = "requests missing"
    # Twilio Lookup optional (if credentials present)
    sid = CONFIG.get("TWILIO_ACCOUNT_SID","")
    token = CONFIG.get("TWILIO_AUTH_TOKEN","")
    if sid and token and requests:
        try:
            lookup_url = f"https://lookups.twilio.com/v1/PhoneNumbers/{e164}?Type=carrier"
            r2 = requests.get(lookup_url, auth=(sid, token), timeout=10)
            if r2.status_code in (200,201):
                out["twilio_lookup"] = r2.json()
            else:
                out["twilio_lookup_error"] = {"status": r2.status_code, "text": r2.text}
        except Exception as e:
            out["twilio_lookup_error"] = str(e)
    else:
        out["twilio_lookup"] = "twilio creds not provided"
    return out

# ----------------------------
# Email checker (format + MX + optional HIBP)
# ----------------------------
def email_check(email):
    out = {"input": email}
    # format
    out["format_ok"] = bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))
    # MX
    if dns:
        try:
            domain = email.split("@")[-1]
            answers = dns.resolver.resolve(domain, "MX", lifetime=6)
            out["mx"] = [r.exchange.to_text(omit_final_dot=True) for r in answers]
        except Exception as e:
            out["mx_error"] = str(e)
    else:
        out["mx_note"] = "dnspython missing"
    # HIBP optional
    hibp = CONFIG.get("HIBP_API_KEY","")
    if hibp and requests:
        try:
            headers = {"hibp-api-key": hibp, "user-agent": CONFIG["USER_AGENT"]}
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.requote_uri(email)}"
            r = requests.get(url, headers=headers, params={"truncateResponse":"false"}, timeout=10)
            if r.status_code == 200:
                out["breaches"] = r.json()
            elif r.status_code == 404:
                out["breaches"] = []
            else:
                out["hibp_error"] = f"status {r.status_code}"
        except Exception as e:
            out["hibp_error"] = str(e)
    else:
        out["hibp_note"] = "hibp not configured"
    # cannot check password or device list
    out["note"] = "This tool does not and cannot retrieve passwords or device lists"
    return out

# ----------------------------
# IP tracker basic
# ----------------------------
def ip_info(ip=None):
    out = {}
    if not requests:
        out["error"] = "requests missing"
        return out
    try:
        if not ip:
            ip = requests.get("https://api.ipify.org?format=json", timeout=6).json().get("ip")
        out["ip"] = ip
        token = CONFIG.get("IPINFO_TOKEN","")
        if token:
            r = requests.get(f"https://ipinfo.io/{ip}/json?token={token}", timeout=8)
            if r.status_code == 200:
                out.update(r.json())
                return out
        # fallback to ipapi
        r2 = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
        if r2.status_code == 200:
            out.update(r2.json())
        else:
            out["error"] = f"ip lookup failed {r2.status_code}"
    except Exception as e:
        out["error"] = str(e)
    return out

# ----------------------------
# Whois / domain lookup
# ----------------------------
def whois_lookup(domain):
    out = {"domain": domain}
    if not whois:
        out["error"] = "python-whois missing"
        return out
    try:
        w = whois.whois(domain)
        out["registrar"] = w.get("registrar")
        out["creation_date"] = w.get("creation_date")
        out["expiration_date"] = w.get("expiration_date")
        out["name_servers"] = w.get("name_servers")
    except Exception as e:
        out["error"] = str(e)
    return out

# ----------------------------
# Device info (local)
# ----------------------------
def device_info():
    out = {}
    out["platform"] = platform.system()
    out["platform_release"] = platform.release()
    out["platform_version"] = platform.version()
    out["architecture"] = platform.machine()
    out["hostname"] = socket.gethostname()
    try:
        out["local_ip"] = socket.gethostbyname(out["hostname"])
    except Exception:
        out["local_ip"] = None
    out["processor"] = platform.processor()
    out["python_version"] = platform.python_version()
    return out

# ----------------------------
# QR generator
# ----------------------------
def generate_qr(text, filename="zxxtirwd_qr.png"):
    if not qrcode:
        return {"error": "qrcode missing"}
    img = qrcode.make(text)
    img.save(filename)
    return {"saved": filename}

# ----------------------------
# Menu (minimal, neon green)
# ----------------------------
def menu():
    while True:
        clear()
        logo()
        print(G + """
[1] YouTube Checker
[2] TikTok Checker
[3] Instagram Checker
[4] WhatsApp Info
[5] Email Checker
[6] IP Tracker
[7] WHOIS Lookup
[8] Device Info
[9] Generate QR
[0] Exit
""" + END)
        choice = input(G + "SELECT > " + END).strip()
        if choice == "": continue
        if choice == "0": break

        if choice == "1":
            ch = input(G + "YOUTUBE CHANNEL/ID/USERNAME : " + END).strip()
            res = youtube_check(ch)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            label = input(G + "SAVE LABEL OR ENTER TO SKIP : " + END).strip()
            if label:
                print(G + "Saved :" + END, save_json(label, {"youtube": res}))
            wait()

        elif choice == "2":
            u = input(G + "TIKTOK USERNAME : " + END).strip().lstrip("@")
            res = tiktok_check(u)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            label = input(G + "SAVE LABEL OR ENTER TO SKIP : " + END).strip()
            if label:
                print(G + "Saved :" + END, save_json(label, {"tiktok": res}))
            wait()

        elif choice == "3":
            u = input(G + "INSTAGRAM USERNAME : " + END).strip().lstrip("@")
            res = instagram_check(u)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            label = input(G + "SAVE LABEL OR ENTER TO SKIP : " + END).strip()
            if label:
                print(G + "Saved :" + END, save_json(label, {"instagram": res}))
            wait()

        elif choice == "4":
            num = input(G + "PHONE E164 +62... : " + END).strip()
            res = whatsapp_info(num)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            label = input(G + "SAVE LABEL OR ENTER TO SKIP : " + END).strip()
            if label:
                print(G + "Saved :" + END, save_json(label, {"whatsapp": res}))
            wait()

        elif choice == "5":
            email = input(G + "EMAIL : " + END).strip()
            res = email_check(email)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            label = input(G + "SAVE LABEL OR ENTER TO SKIP : " + END).strip()
            if label:
                print(G + "Saved :" + END, save_json(label, {"email": res}))
            wait()

        elif choice == "6":
            ip = input(G + "IP LEAVE BLANK FOR YOUR IP : " + END).strip() or None
            res = ip_info(ip)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            label = input(G + "SAVE LABEL OR ENTER TO SKIP : " + END).strip()
            if label:
                print(G + "Saved :" + END, save_json(label, {"ip": res}))
            wait()

        elif choice == "7":
            d = input(G + "DOMAIN : " + END).strip()
            res = whois_lookup(d)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            label = input(G + "SAVE LABEL OR ENTER TO SKIP : " + END).strip()
            if label:
                print(G + "Saved :" + END, save_json(label, {"whois": res}))
            wait()

        elif choice == "8":
            res = device_info()
            print(json.dumps(res, indent=2, ensure_ascii=False))
            wait()

        elif choice == "9":
            t = input(G + "TEXT OR URL FOR QR : " + END).strip()
            res = generate_qr(t)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            wait()

        else:
            print(R + "INVALID" + END)
            time.sleep(0.6)

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n" + G + "EXIT" + END)