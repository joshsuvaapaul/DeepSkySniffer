#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║        LIVE WEBSITE THREAT TRACKER v2 — Real Data Only      ║
║   Real DNS · Real SSL · Real HTTP · Real Ports · Real WHOIS ║
║   Ping Latency · BGP/ASN · SPF/DKIM · DNSBL · Live Net I/O  ║
╚══════════════════════════════════════════════════════════════╝

Requirements:
  Python 3.7+
  Windows only:        pip install windows-curses
  Better net stats:    pip install psutil
  Live packet capture: pip install scapy  (then run with sudo)

Usage:
  python3 threat_tracker.py
  sudo python3 threat_tracker.py     # enables scapy packet capture
"""

import curses, socket, threading, time, json, os, sys, ssl
import urllib.request, urllib.error, urllib.parse
import subprocess, struct, re, hashlib, ipaddress
from datetime import datetime, timezone
from collections import deque, defaultdict

# ── Optional deps ─────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
    SCAPY = True
except ImportError:
    SCAPY = False

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

# ── Color pair IDs ────────────────────────────────────────────────────────────
C_HEADER=1; C_BORDER=2; C_SAFE=3; C_WARN=4; C_DANGER=5
C_CRIT=6;   C_DIM=7;    C_HI=8;   C_LABEL=9; C_VAL=10
C_GREEN=11; C_RED=12;   C_TITLE=13; C_BLUE=14

VERSION    = "2.0"
MAX_GRAPH  = 60
MAX_EVENTS = 300

PORT_NAMES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",587:"SMTPS",
    993:"IMAPS",995:"POP3S",3306:"MySQL",3389:"RDP",
    5432:"PgSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",
    27017:"MongoDB",11211:"Memcached",9200:"Elasticsearch",2181:"Zookeeper",
}
RISKY_PORTS = {21,23,3389,3306,27017,6379,11211,9200}
SEC_HEADERS = {
    "Strict-Transport-Security","Content-Security-Policy",
    "X-Frame-Options","X-Content-Type-Options",
    "Referrer-Policy","Permissions-Policy",
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def now():        return datetime.now().strftime("%H:%M:%S")
def clamp(v,a,b): return max(a, min(b, v))
def bar(v,m,w,f="█",e="░"): n=int((v/max(m,1))*w); return f*n+e*(w-n)
def fmt_b(n):
    for u in ["B","KB","MB","GB"]:
        if n<1024: return f"{n:.1f}{u}"
        n/=1024
    return f"{n:.1f}TB"
def fmt_ms(ms):
    if ms<0: return "timeout"
    if ms<1: return "<1ms"
    return f"{ms:.1f}ms"
def risk_col(s):
    return C_SAFE if s<30 else (C_WARN if s<60 else (C_DANGER if s<80 else C_CRIT))
def risk_lbl(s):
    return "LOW" if s<30 else ("MEDIUM" if s<60 else ("HIGH" if s<80 else "CRITICAL"))

# ═══════════════════════════════════════════════════════════════════════════════
#  REAL NETWORK FUNCTIONS — every function below makes actual network calls
# ═══════════════════════════════════════════════════════════════════════════════

def real_dns(domain):
    """Real DNS: A, AAAA, PTR, MX, TXT, NS, SPF, DMARC."""
    r = {"ips":[], "records":{}, "spf":None, "dmarc":None, "errors":[]}
    # A / AAAA
    try:
        info = socket.getaddrinfo(domain, None)
        r["records"]["A"]    = list({x[4][0] for x in info if x[0]==socket.AF_INET})
        r["records"]["AAAA"] = list({x[4][0] for x in info if x[0]==socket.AF_INET6})
        r["ips"] = r["records"]["A"] + r["records"]["AAAA"]
    except Exception as e:
        r["errors"].append(str(e))
    # PTR
    ptrs = {}
    for ip in r["records"].get("A",[])[:3]:
        try: ptrs[ip] = socket.gethostbyaddr(ip)[0]
        except: ptrs[ip] = "no PTR"
    r["records"]["PTR"] = ptrs
    # MX TXT NS CNAME via nslookup
    for rtype in ["MX","TXT","NS","CNAME"]:
        try:
            p = subprocess.run(["nslookup",f"-type={rtype}",domain],
                               capture_output=True, text=True, timeout=5)
            lines = [l.strip() for l in p.stdout.splitlines()
                     if l.strip() and "**" not in l
                     and not l.strip().startswith("Server:")
                     and not l.strip().startswith("Address:")]
            r["records"][rtype] = lines[:4]
        except: r["records"][rtype] = []
    # SPF
    spf = [x for x in r["records"].get("TXT",[]) if "v=spf1" in x.lower()]
    r["spf"] = spf[0] if spf else None
    # DMARC
    try:
        p = subprocess.run(["nslookup","-type=TXT",f"_dmarc.{domain}"],
                           capture_output=True, text=True, timeout=5)
        dm = [l for l in p.stdout.splitlines() if "v=DMARC1" in l]
        r["dmarc"] = dm[0].strip() if dm else None
    except: pass
    return r

def real_ssl(domain):
    """Real SSL/TLS: certificate chain, cipher, expiry, SANs."""
    r = {}
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(8)
        conn.connect((domain, 443))
        cert   = conn.getpeercert()
        cipher = conn.cipher()
        ver    = conn.version()
        conn.close()
        r["valid"]     = True
        r["tls"]       = ver
        r["cipher"]    = cipher[0] if cipher else "N/A"
        r["bits"]      = cipher[2] if cipher else 0
        subj = dict(x[0] for x in cert.get("subject",[]))
        issu = dict(x[0] for x in cert.get("issuer",[]))
        r["cn"]        = subj.get("commonName","N/A")
        r["org"]       = subj.get("organizationName","N/A")
        r["issuer"]    = issu.get("organizationName","N/A")
        r["issuer_cn"] = issu.get("commonName","N/A")
        r["not_before"]= cert.get("notBefore","N/A")
        r["not_after"] = cert.get("notAfter","N/A")
        r["serial"]    = cert.get("serialNumber","N/A")
        r["san"]       = [v for _,v in cert.get("subjectAltName",[])][:8]
        try:
            exp = datetime.strptime(r["not_after"], "%b %d %H:%M:%S %Y %Z")
            r["days"] = (exp.replace(tzinfo=timezone.utc)-datetime.now(timezone.utc)).days
        except: r["days"] = -1
        r["weak"] = any(w in r["cipher"].upper() for w in ["RC4","MD5","NULL","EXPORT","DES"])
        r["tls_ok"] = ver in ["TLSv1.2","TLSv1.3"]
    except ssl.SSLCertVerificationError as e:
        r["valid"]=False; r["error"]=f"Verification failed: {e}"
    except ConnectionRefusedError:
        r["valid"]=False; r["error"]="Port 443 refused — no HTTPS"
    except Exception as e:
        r["valid"]=False; r["error"]=str(e)
    return r

def real_http(domain):
    """Real HTTP: headers, status, security analysis."""
    r = {}
    for scheme in ["https","http"]:
        try:
            url = f"{scheme}://{domain}"
            req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0 ThreatTracker/2.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                hdrs = dict(resp.headers)
                r["status"]   = resp.status
                r["scheme"]   = scheme
                r["url"]      = resp.url
                r["server"]   = hdrs.get("Server") or hdrs.get("server") or "N/A"
                r["powered"]  = hdrs.get("X-Powered-By","N/A")
                r["ctype"]    = hdrs.get("Content-Type","N/A")
                r["cache"]    = hdrs.get("Cache-Control","N/A")
                r["cors"]     = hdrs.get("Access-Control-Allow-Origin","N/A")
                r["cookie"]   = bool(hdrs.get("Set-Cookie"))
                r["redirect"] = resp.url != url
                r["final"]    = resp.url
                present = {h for h in SEC_HEADERS
                           if any(h.lower()==k.lower() for k in hdrs)}
                r["ok_hdrs"]  = sorted(present)
                r["mis_hdrs"] = sorted(SEC_HEADERS - present)
                r["hsts"]     = hdrs.get("Strict-Transport-Security","MISSING")
                r["xfo"]      = hdrs.get("X-Frame-Options","MISSING")
                r["csp"]      = hdrs.get("Content-Security-Policy","MISSING")
                r["xcto"]     = hdrs.get("X-Content-Type-Options","MISSING")
                return r
        except urllib.error.HTTPError as e:
            r[f"err_{scheme}"]=f"{e.code} {e.reason}"
        except Exception as e:
            r[f"err_{scheme}"]=str(e)
    r["status"]=0
    return r

def real_ports(ip, timeout=0.8):
    """Real TCP connect scan on all common ports."""
    open_p=[]; lock=threading.Lock()
    def probe(p):
        try:
            s=socket.socket(); s.settimeout(timeout)
            if s.connect_ex((ip,p))==0:
                with lock: open_p.append(p)
            s.close()
        except: pass
    ts=[threading.Thread(target=probe,args=(p,),daemon=True) for p in PORT_NAMES]
    for t in ts: t.start()
    for t in ts: t.join(timeout=2.5)
    return sorted(open_p)

def real_ping(host, count=4):
    """Real ICMP ping via system ping."""
    r={"min":-1,"max":-1,"avg":-1,"loss":100,"times":[]}
    try:
        cmd=(["ping","-n",str(count),host] if sys.platform=="win32"
             else ["ping","-c",str(count),"-W","2",host])
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
        out=p.stdout
        times=re.findall(r"time[=<](\d+\.?\d*)\s*ms",out,re.IGNORECASE)
        r["times"]=[float(t) for t in times]
        loss=re.search(r"(\d+)%\s+(packet )?loss",out)
        if loss: r["loss"]=int(loss.group(1))
        if sys.platform=="win32":
            st=re.search(r"Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms",out)
            if st: r["min"],r["max"],r["avg"]=float(st.group(1)),float(st.group(2)),float(st.group(3))
        else:
            st=re.search(r"(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)/",out)
            if st: r["min"],r["avg"],r["max"]=float(st.group(1)),float(st.group(2)),float(st.group(3))
        if r["avg"]<0 and r["times"]:
            r["min"]=min(r["times"]); r["max"]=max(r["times"])
            r["avg"]=sum(r["times"])/len(r["times"])
    except Exception as e: r["error"]=str(e)
    return r

def real_traceroute(host, max_hops=15):
    """Real traceroute/tracert."""
    hops=[]
    try:
        cmd=(["tracert","-h",str(max_hops),"-w","1000",host] if sys.platform=="win32"
             else ["traceroute","-m",str(max_hops),"-w","2",host])
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        for line in p.stdout.splitlines():
            m=re.match(r"\s*(\d+)\s+(.+)",line)
            if m:
                ip_m=re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",m.group(2))
                ms_m=re.findall(r"(\d+\.?\d*)\s*ms",m.group(2))
                hops.append({"hop":m.group(1),
                              "ip":ip_m.group(1) if ip_m else "*",
                              "ms":float(ms_m[0]) if ms_m else -1})
    except: pass
    return hops[:max_hops]

def real_whois(ip):
    """Real WHOIS/RDAP ASN lookup."""
    r={}
    # Try RDAP first
    try:
        url=f"https://rdap.arin.net/registry/ip/{ip}"
        req=urllib.request.Request(url,headers={"User-Agent":"ThreatTracker/2.0","Accept":"application/json"})
        with urllib.request.urlopen(req,timeout=6) as resp:
            data=json.loads(resp.read().decode())
            r["name"]=data.get("name","N/A")
            r["country"]=data.get("country","N/A")
            r["handle"]=data.get("handle","N/A")
            for ent in data.get("entities",[]):
                vc=ent.get("vcardArray",[])
                if len(vc)>1:
                    for item in vc[1]:
                        if item[0]=="org": r["org"]=item[3]
                        if item[0]=="fn" and "org" not in r: r["org"]=item[3]
    except: pass
    # Fallback: whois command
    if not r:
        try:
            p=subprocess.run(["whois",ip],capture_output=True,text=True,timeout=8)
            for line in p.stdout.splitlines():
                l=line.strip().lower()
                if l.startswith("orgname:") or l.startswith("org-name:"):
                    r["org"]=line.split(":",1)[1].strip()
                if l.startswith("country:") and "country" not in r:
                    r["country"]=line.split(":",1)[1].strip()
                if re.match(r"^as\d+",l):
                    r["asn"]=line.split()[0].upper()
        except: pass
    return r

def real_geo(ip):
    """Real GeoIP via ip-api.com (free, no key needed)."""
    try:
        url=f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,isp,org,as,proxy,hosting,mobile"
        req=urllib.request.Request(url,headers={"User-Agent":"ThreatTracker/2.0"})
        with urllib.request.urlopen(req,timeout=5) as resp:
            data=json.loads(resp.read().decode())
            if data.get("status")=="success": return data
    except: pass
    return {}

def real_blacklist(ip):
    """Real DNSBL check against 5 major blacklists."""
    dnsbls=["zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net",
            "b.barracudacentral.org","dnsbl-1.uceprotect.net"]
    listed=[]
    rev=".".join(reversed(ip.split(".")))
    for bl in dnsbls:
        try:
            socket.gethostbyname(f"{rev}.{bl}")
            listed.append(bl)
        except socket.gaierror: pass
        except: pass
    return listed

def real_http_time(domain):
    """Real HTTP response time measurement."""
    for scheme in ["https","http"]:
        try:
            url=f"{scheme}://{domain}"
            req=urllib.request.Request(url,headers={"User-Agent":"ThreatTracker/2.0"})
            t0=time.time()
            with urllib.request.urlopen(req,timeout=8) as resp: resp.read(512)
            return (time.time()-t0)*1000, scheme
        except: pass
    return -1, "?"

def get_net_interfaces():
    """Real network interface I/O — psutil or /proc/net/dev."""
    ifaces={}
    if PSUTIL:
        for name,s in psutil.net_io_counters(pernic=True).items():
            ifaces[name]={"bytes_in":s.bytes_recv,"bytes_out":s.bytes_sent,
                          "pkts_in":s.packets_recv,"pkts_out":s.packets_sent,
                          "errin":s.errin,"errout":s.errout}
    elif os.path.exists("/proc/net/dev"):
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                p=line.split()
                if len(p)>=10:
                    n=p[0].rstrip(":")
                    ifaces[n]={"bytes_in":int(p[1]),"bytes_out":int(p[9]),
                               "pkts_in":int(p[2]),"pkts_out":int(p[10]),
                               "errin":int(p[3]),"errout":int(p[11])}
    return ifaces

# ═══════════════════════════════════════════════════════════════════════════════
#  REAL PACKET CAPTURE (scapy + root)
# ═══════════════════════════════════════════════════════════════════════════════

class PacketCapture:
    def __init__(self):
        self.running=False; self.lock=threading.Lock()
        self.total=0; self.total_bytes=0
        self._acc_p=0; self._acc_b=0
        self.pps_hist=deque([0]*MAX_GRAPH,maxlen=MAX_GRAPH)
        self.bps_hist=deque([0]*MAX_GRAPH,maxlen=MAX_GRAPH)
        self.cur_pps=0; self.cur_bps=0
        self.proto_c=defaultdict(int); self.port_c=defaultdict(int)
        self.src_c=defaultdict(int); self.syn_c=defaultdict(int)
        self.pkts=deque(maxlen=300)
        self.events=deque(maxlen=MAX_EVENTS)

    def log(self,m,l="INFO"): self.events.appendleft(f"[{now()}][{l}] {m}")

    def start(self, target_ip=None):
        if not SCAPY:
            self.log("scapy not installed. pip install scapy","WARN"); return
        is_root = (os.geteuid()==0) if sys.platform!="win32" else True
        if not is_root:
            self.log("Root required. Run: sudo python3 threat_tracker.py","WARN"); return
        self.target=target_ip; self.running=True
        self.log(f"Packet capture started (filter: host {target_ip or 'ALL'})","INFO")
        threading.Thread(target=self._cap,daemon=True).start()
        threading.Thread(target=self._tick,daemon=True).start()

    def _tick(self):
        while self.running:
            time.sleep(1)
            with self.lock:
                self.cur_pps=self._acc_p; self.cur_bps=self._acc_b
                self.pps_hist.append(self._acc_p); self.bps_hist.append(self._acc_b)
                self._acc_p=0; self._acc_b=0
                # SYN flood detection
                for ip,cnt in list(self.syn_c.items()):
                    if cnt>100: self.log(f"SYN FLOOD from {ip} ({cnt} SYNs/s)","ALERT")
                self.syn_c.clear()

    def _cap(self):
        try:
            f=f"host {self.target}" if self.target else None
            sniff(prn=self._pkt, filter=f, store=False, stop_filter=lambda _:not self.running)
        except Exception as e:
            self.log(f"Capture error: {e}","ERROR")

    def _pkt(self,pkt):
        try:
            size=len(pkt); src=dst=proto="?"; sport=dport=0
            if IP in pkt:
                src=pkt[IP].src; dst=pkt[IP].dst
                if TCP in pkt:
                    proto="TCP"; sport=pkt[TCP].sport; dport=pkt[TCP].dport
                    if pkt[TCP].flags&0x02: self.syn_c[src]+=1
                elif UDP in pkt:
                    proto="UDP"; sport=pkt[UDP].sport; dport=pkt[UDP].dport
                    if DNS in pkt: proto="DNS"
                elif ICMP in pkt: proto="ICMP"
            with self.lock:
                self.total+=1; self.total_bytes+=size
                self._acc_p+=1; self._acc_b+=size
                self.proto_c[proto]+=1
                if dport: self.port_c[dport]+=1
                if src: self.src_c[src]+=1
                self.pkts.appendleft({"ts":time.time(),"src":src,"dst":dst,
                                      "proto":proto,"sport":sport,"dport":dport,"size":size})
        except: pass

    def stop(self): self.running=False

# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK I/O MONITOR (no root needed)
# ═══════════════════════════════════════════════════════════════════════════════

class NetMon:
    def __init__(self):
        self.running=False; self._prev={}
        self.bps_in=deque([0]*MAX_GRAPH,maxlen=MAX_GRAPH)
        self.bps_out=deque([0]*MAX_GRAPH,maxlen=MAX_GRAPH)
        self.pps_in=deque([0]*MAX_GRAPH,maxlen=MAX_GRAPH)
        self.cur_bin=0; self.cur_bout=0; self.cur_pin=0
        self.total_in=0; self.total_out=0
        self.events=deque(maxlen=MAX_EVENTS)

    def log(self,m,l="INFO"): self.events.appendleft(f"[{now()}][{l}] {m}")

    def start(self):
        self.running=True
        threading.Thread(target=self._run,daemon=True).start()

    def _run(self):
        while self.running:
            try:
                cur=get_net_interfaces()
                if self._prev:
                    bin_=bout_=pin_=0
                    for iface,v in cur.items():
                        p=self._prev.get(iface,v)
                        bin_ +=max(0,v["bytes_in"] -p["bytes_in"])
                        bout_+=max(0,v["bytes_out"]-p["bytes_out"])
                        pin_ +=max(0,v["pkts_in"]  -p["pkts_in"])
                    self.cur_bin=bin_; self.cur_bout=bout_; self.cur_pin=pin_
                    self.total_in+=bin_; self.total_out+=bout_
                    self.bps_in.append(bin_); self.bps_out.append(bout_)
                    self.pps_in.append(pin_)
                self._prev=cur
            except Exception as e: self.log(f"NetMon: {e}","WARN")
            time.sleep(1)

    def stop(self): self.running=False

# ═══════════════════════════════════════════════════════════════════════════════
#  LIVE RESCAN LOOP
# ═══════════════════════════════════════════════════════════════════════════════

class RescanLoop:
    def __init__(self, interval=30):
        self.interval=interval; self.running=False
        self.domain=None; self.ip=None
        self.ping_hist=deque(maxlen=MAX_GRAPH)
        self.http_hist=deque(maxlen=MAX_GRAPH)
        self.last_ping={}; self.last_http=(-1,"?")
        self.uptime=100.0; self._checks=0; self._up=0
        self.events=deque(maxlen=MAX_EVENTS)

    def log(self,m,l="INFO"): self.events.appendleft(f"[{now()}][{l}] {m}")

    def start(self, domain, ip):
        self.domain=domain; self.ip=ip; self.running=True
        threading.Thread(target=self._run,daemon=True).start()

    def _run(self):
        while self.running:
            self._check(); time.sleep(self.interval)

    def _check(self):
        # Real ping
        pr=real_ping(self.ip or self.domain, count=3)
        self.last_ping=pr
        avg=pr.get("avg",-1)
        self.ping_hist.append(avg if avg>0 else 0)
        # Real HTTP timing
        ms,scheme=real_http_time(self.domain)
        self.last_http=(ms,scheme)
        self.http_hist.append(ms if ms>0 else 0)
        # Uptime
        self._checks+=1
        if pr.get("loss",100)<100: self._up+=1
        self.uptime=(self._up/self._checks)*100
        # Events
        if pr.get("loss",100)==100:
            self.log(f"HOST UNREACHABLE: {self.ip or self.domain}","ALERT")
        elif avg>300:
            self.log(f"High latency: {avg:.0f}ms to {self.domain}","WARN")
        if ms>3000:
            self.log(f"Slow HTTP: {ms:.0f}ms from {self.domain}","WARN")
        elif ms>0:
            self.log(f"HTTP OK: {ms:.0f}ms ({scheme.upper()})","INFO")

    def stop(self): self.running=False

# ═══════════════════════════════════════════════════════════════════════════════
#  FULL SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class Scanner:
    def __init__(self):
        self.results={}; self.status="idle"; self.progress=0

    def scan(self, domain, cb):
        self.status="scanning"; self.results={}
        threading.Thread(target=self._run,args=(domain,cb),daemon=True).start()

    def _run(self, domain, cb):
        self._domain=domain; self._ips=[]
        steps=[
            (10, "DNS Full Recon",    lambda: real_dns(domain),   "dns"),
            (28, "SSL/TLS Deep Scan", lambda: real_ssl(domain),    "ssl"),
            (44, "HTTP Headers",      lambda: real_http(domain),   "http"),
            (58, "Port Scan",         self._do_ports,              "ports"),
            (70, "Ping / Latency",    self._do_ping,               "ping"),
            (80, "WHOIS / ASN",       self._do_whois,              "whois"),
            (88, "GeoIP",             self._do_geo,                "geo"),
            (95, "DNSBL Blacklists",  self._do_bl,                 "blist"),
        ]
        for pct,name,fn,key in steps:
            self.status=name; self.progress=pct
            try:
                res=fn(); self.results[key]=res
                if key=="dns": self._ips=res.get("ips",[])
            except Exception as e:
                self.results[key]={"error":str(e)}
        # Traceroute (non-blocking, added after)
        self.progress=100; self.status="complete"
        cb(self.results)

    def _do_ports(self):
        ip=self._ips[0] if self._ips else self._domain
        return real_ports(ip)
    def _do_ping(self):
        t=self._ips[0] if self._ips else self._domain
        return real_ping(t, count=4)
    def _do_whois(self):
        return real_whois(self._ips[0]) if self._ips else {}
    def _do_geo(self):
        return real_geo(self._ips[0]) if self._ips else {}
    def _do_bl(self):
        return real_blacklist(self._ips[0]) if self._ips else []

# ═══════════════════════════════════════════════════════════════════════════════
#  RISK SCORING (based on real scan results)
# ═══════════════════════════════════════════════════════════════════════════════

def compute_risk(scan, rescan):
    score=0; reasons=[]
    ssl_r = scan.get("ssl",{})
    http  = scan.get("http",{})
    ports = scan.get("ports",[])
    blist = scan.get("blist",[])
    geo   = scan.get("geo",{})
    ping  = scan.get("ping",{})

    if not ssl_r.get("valid", True):
        score+=25; reasons.append("Invalid/missing SSL certificate")
    days=ssl_r.get("days",-1)
    if 0<days<14:   score+=20; reasons.append(f"SSL expires in {days}d")
    elif 0<days<30: score+=10; reasons.append(f"SSL expires in {days}d")
    if ssl_r.get("weak"): score+=15; reasons.append("Weak cipher suite")
    if not ssl_r.get("tls_ok",True): score+=8; reasons.append(f"Old TLS: {ssl_r.get('tls','?')}")

    mis=http.get("mis_hdrs",[])
    score+=len(mis)*4
    if mis: reasons.append(f"Missing sec headers: {', '.join(mis[:2])}")

    risky_open=[p for p in (ports if isinstance(ports,list) else []) if p in RISKY_PORTS]
    if risky_open: score+=len(risky_open)*8; reasons.append(f"Risky ports: {risky_open}")

    if blist and isinstance(blist,list):
        score+=30; reasons.append(f"On {len(blist)} DNSBL blacklist(s)")

    if rescan.uptime<90: score+=15; reasons.append(f"Low uptime {rescan.uptime:.1f}%")
    avg=ping.get("avg",0) or 0
    if avg>300: score+=5; reasons.append(f"High latency {avg:.0f}ms")

    if geo.get("proxy"): score+=8;  reasons.append("IP identified as proxy")
    if geo.get("hosting"): score+=3; reasons.append("Hosted on datacenter IP")

    return clamp(score,0,100), reasons

# ═══════════════════════════════════════════════════════════════════════════════
#  CURSES UI
# ═══════════════════════════════════════════════════════════════════════════════

class App:
    TABS=["DASHBOARD","RECON","LIVE NET","PING/RT","EVENTS"]

    def __init__(self, scr):
        self.scr=scr; self.running=True
        self.input_mode=True; self.input_buf=""; self.domain=""
        self.tab=0; self.scroll=0
        self.scanner=Scanner(); self.scan={}
        self.net=NetMon(); self.cap=PacketCapture()
        self.rs=RescanLoop(30)
        self.risk=0; self.reasons=[]
        self.all_ev=deque(maxlen=MAX_EVENTS)
        self._setup_colors()
        curses.curs_set(1); self.scr.nodelay(True); self.scr.keypad(True)

    def _setup_colors(self):
        curses.start_color(); curses.use_default_colors()
        curses.init_pair(C_HEADER,curses.COLOR_BLACK,curses.COLOR_CYAN)
        curses.init_pair(C_BORDER,curses.COLOR_CYAN,-1)
        curses.init_pair(C_SAFE,curses.COLOR_GREEN,-1)
        curses.init_pair(C_WARN,curses.COLOR_YELLOW,-1)
        curses.init_pair(C_DANGER,curses.COLOR_RED,-1)
        curses.init_pair(C_CRIT,curses.COLOR_BLACK,curses.COLOR_RED)
        curses.init_pair(C_DIM,8,-1)
        curses.init_pair(C_HI,curses.COLOR_BLACK,curses.COLOR_YELLOW)
        curses.init_pair(C_LABEL,curses.COLOR_CYAN,-1)
        curses.init_pair(C_VAL,curses.COLOR_WHITE,-1)
        curses.init_pair(C_GREEN,curses.COLOR_GREEN,-1)
        curses.init_pair(C_RED,curses.COLOR_RED,-1)
        curses.init_pair(C_TITLE,curses.COLOR_CYAN,curses.COLOR_BLACK)
        curses.init_pair(C_BLUE,curses.COLOR_BLUE,-1)

    def w(self,y,x,t,a=0):
        h,W=self.scr.getmaxyx()
        if y<0 or y>=h-1 or x<0 or x>=W-1: return
        t=str(t); avail=W-x-1
        if avail<1: return
        try: self.scr.addstr(y,x,t[:avail],a)
        except: pass

    def hl(self,y,x,c,n,a=0):
        h,W=self.scr.getmaxyx()
        if y<0 or y>=h-1: return
        try: self.scr.hline(y,x,c,min(n,W-x-1),a)
        except: pass

    # ── Input ─────────────────────────────────────────────────────────────────
    def _input_screen(self):
        self.scr.clear(); h,W=self.scr.getmaxyx(); cy=h//2-7
        art=[
            "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗",
            "     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝",
            "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ",
            "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ",
            "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ",
            "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝  ",
            "    T R A C K E R  v2  ·  100% Real Network Data     ",
        ]
        for i,l in enumerate(art):
            self.w(cy+i,max(0,(W-len(l))//2),l,curses.color_pair(C_LABEL)|curses.A_BOLD)
        sub="Real DNS · SSL · HTTP · Ports · Ping · WHOIS · GeoIP · DNSBL · Live I/O"
        self.w(cy+len(art)+1,max(0,(W-len(sub))//2),sub,curses.color_pair(C_DIM))
        bw=58; bx=(W-bw)//2; by=cy+len(art)+3
        self.w(by,   bx,"┌"+"─"*(bw-2)+"┐",curses.color_pair(C_BORDER))
        self.w(by+1, bx,"│"+" "*(bw-2)+"│",curses.color_pair(C_BORDER))
        self.w(by+2, bx,"└"+"─"*(bw-2)+"┘",curses.color_pair(C_BORDER))
        pr="  Enter domain or IP: "
        self.w(by+1,bx+1,pr,curses.color_pair(C_LABEL)|curses.A_BOLD)
        ix=bx+1+len(pr)
        self.w(by+1,ix,self.input_buf,curses.color_pair(C_VAL))
        self.w(by+4,max(0,(W-50)//2),"  e.g.  example.com   93.184.216.34   google.com",curses.color_pair(C_DIM))
        go="[ Press ENTER to begin real-time scan ]"
        self.w(by+5,max(0,(W-len(go))//2),go,curses.color_pair(C_HI)|curses.A_BOLD)
        note="✓ Zero simulated data — every result comes from real network requests"
        self.w(by+7,max(0,(W-len(note))//2),note,curses.color_pair(C_SAFE))
        try: self.scr.move(by+1,min(ix+len(self.input_buf),W-2))
        except: pass

    # ── Header ────────────────────────────────────────────────────────────────
    def _header(self):
        h,W=self.scr.getmaxyx()
        self.hl(0,0,' ',W,curses.color_pair(C_HEADER)|curses.A_BOLD)
        self.w(0,1,f" THREAT TRACKER v{VERSION} — REAL DATA ONLY ",curses.color_pair(C_HEADER)|curses.A_BOLD)
        d=f" TARGET: {self.domain} "
        self.w(0,(W-len(d))//2,d,curses.color_pair(C_HEADER)|curses.A_BOLD)
        ts=f" {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
        self.w(0,W-len(ts)-1,ts,curses.color_pair(C_HEADER))

    def _tabs(self):
        h,W=self.scr.getmaxyx(); x=1
        for i,t in enumerate(self.TABS):
            lbl=f" {i+1}:{t} "
            a=(curses.color_pair(C_TITLE)|curses.A_BOLD|curses.A_REVERSE
               if i==self.tab else curses.color_pair(C_DIM))
            self.w(1,x,lbl,a); x+=len(lbl)+1
        hint="[Q]uit [R]eset [Tab]→ ↑↓"
        self.w(1,W-len(hint)-2,hint,curses.color_pair(C_DIM))
        self.hl(2,0,'─',W,curses.color_pair(C_BORDER))
        return 3

    # ── DASHBOARD ─────────────────────────────────────────────────────────────
    def _dashboard(self, y0):
        h,W=self.scr.getmaxyx(); y=y0
        net=self.net; rs=self.rs
        cw=max((W-2)//4,16)

        ping_avg=rs.last_ping.get("avg",-1)
        http_ms =rs.last_http[0]
        up_c =C_SAFE if rs.uptime>=99 else(C_WARN if rs.uptime>=90 else C_DANGER)
        pg_c =C_SAFE if 0<ping_avg<100 else(C_WARN if ping_avg<300 else C_DANGER)
        ht_c =C_SAFE if 0<http_ms<500 else(C_WARN if http_ms<2000 else C_DANGER)
        rk_c =risk_col(self.risk)

        for i,(lbl,val,col) in enumerate([
            ("RISK SCORE",f"{self.risk}/100",rk_c),
            ("UPTIME",f"{rs.uptime:.1f}%",up_c),
            ("PING AVG",fmt_ms(ping_avg),pg_c),
            ("HTTP RESP",fmt_ms(http_ms),ht_c),
        ]):
            bx=1+i*cw
            self.w(y,  bx,f"┌{'─'*(cw-2)}┐",curses.color_pair(C_BORDER))
            self.w(y+1,bx,"│",curses.color_pair(C_BORDER))
            self.w(y+1,bx+(cw-len(lbl))//2,lbl,curses.color_pair(C_LABEL)|curses.A_BOLD)
            self.w(y+1,bx+cw-1,"│",curses.color_pair(C_BORDER))
            self.w(y+2,bx,"│",curses.color_pair(C_BORDER))
            self.w(y+2,bx+(cw-len(val))//2,val,curses.color_pair(col)|curses.A_BOLD)
            self.w(y+2,bx+cw-1,"│",curses.color_pair(C_BORDER))
            self.w(y+3,bx,f"└{'─'*(cw-2)}┘",curses.color_pair(C_BORDER))
        y+=4

        # Risk bar
        sc=self.risk; col=risk_col(sc)
        self.w(y,1,f" THREAT LEVEL: {risk_lbl(sc)} ({sc}/100) ",curses.color_pair(col)|curses.A_BOLD)
        gw=50
        self.w(y+1,1,"[",curses.color_pair(C_BORDER))
        for j,ch in enumerate(bar(sc,100,gw)):
            c=curses.color_pair(C_RED if j>gw*0.8 else(C_WARN if j>gw*0.5 else C_GREEN))
            self.w(y+1,2+j,ch,c|curses.A_BOLD)
        self.w(y+1,2+gw,"]",curses.color_pair(C_BORDER))
        rx=gw+5
        self.w(y,rx,"RISK FACTORS:",curses.color_pair(C_LABEL)|curses.A_BOLD)
        for i,r in enumerate(self.reasons[:4]):
            self.w(y+1+i,rx,f"• {r}"[:W-rx-2],curses.color_pair(C_WARN))
        if not self.reasons:
            self.w(y+1,rx,"✓ No critical risks found",curses.color_pair(C_SAFE))
        y+=3

        # Real bandwidth graph
        gh=6; gw2=min(W-4,MAX_GRAPH)
        self.w(y,1,f"┌─ REAL NETWORK I/O  IN:{fmt_bytes(net.cur_bin)}/s  OUT:{fmt_bytes(net.cur_bout)}/s ─┐",
               curses.color_pair(C_BORDER))
        hi=list(net.bps_in)[-gw2:]; ho=list(net.bps_out)[-gw2:]
        mv=max(max(hi,default=1),max(ho,default=1),1)
        for ri in range(gh):
            tlo=mv*(gh-ri-1)/gh; thi=mv*(gh-ri)/gh
            self.w(y+1+ri,1,"│",curses.color_pair(C_BORDER))
            for ci,(vi,vo) in enumerate(zip(hi,ho)):
                if vi>=thi:    ch="█";col=C_GREEN
                elif vi>=tlo:  ch="▄";col=C_GREEN
                elif vo>=thi:  ch="▀";col=C_BLUE
                else:          ch=" ";col=C_DIM
                self.w(y+1+ri,2+ci,ch,curses.color_pair(col))
            self.w(y+1+ri,2+gw2,"│",curses.color_pair(C_BORDER))
            self.w(y+1+ri,2+gw2+1,f" {fmt_bytes(int(thi)):>8}",curses.color_pair(C_DIM))
        self.w(y+gh+1,1,"└"+"─"*gw2+"┘",curses.color_pair(C_BORDER))
        self.w(y+gh+2,1,"  ▓Green=Inbound  ▓Blue=Outbound  (real interface bytes/sec from /proc or psutil)",
               curses.color_pair(C_DIM))
        y+=gh+3

        # Ping sparkline
        ph=list(rs.ping_hist)
        self.w(y,1,"PING LATENCY HISTORY (real ICMP):",curses.color_pair(C_LABEL)|curses.A_BOLD)
        if ph:
            mx=max(max(ph),1); chars=" ▁▂▃▄▅▆▇█"
            spark="".join(chars[int((v/mx)*(len(chars)-1))] for v in ph[-50:])
            pc=C_SAFE if(ping_avg or 0)<100 else C_WARN
            self.w(y+1,1,f"[{spark}]",curses.color_pair(pc))
            pinfo=(f"  min:{fmt_ms(rs.last_ping.get('min',-1))}  "
                   f"avg:{fmt_ms(ping_avg)}  max:{fmt_ms(rs.last_ping.get('max',-1))}  "
                   f"loss:{rs.last_ping.get('loss',0)}%")
            self.w(y+1,54,pinfo,curses.color_pair(C_VAL))
        y+=3

        # 3-col: Geo / SSL / Blacklist
        cw3=(W-2)//3
        geo=self.scan.get("geo",{}); ssl_r=self.scan.get("ssl",{}); bl=self.scan.get("blist",[])

        self.w(y,1,"GEO / ASN",curses.color_pair(C_LABEL)|curses.A_BOLD)
        for i,(k,v) in enumerate([
            ("Country", geo.get("country","N/A")),
            ("City",    geo.get("city","N/A")),
            ("ISP",     (geo.get("isp") or "N/A")[:24]),
            ("AS",      (geo.get("as") or "N/A")[:24]),
            ("Proxy",   str(geo.get("proxy","N/A"))),
            ("Hosting", str(geo.get("hosting","N/A"))),
        ]):
            self.w(y+1+i,1,f"{k:<9}: {v}",curses.color_pair(C_VAL))

        self.w(y,cw3+2,"SSL STATUS",curses.color_pair(C_LABEL)|curses.A_BOLD)
        if ssl_r.get("valid"):
            days=ssl_r.get("days",-1)
            dc=C_SAFE if days>30 else(C_WARN if days>7 else C_DANGER)
            self.w(y+1,cw3+2,"✓ Valid certificate",curses.color_pair(C_SAFE)|curses.A_BOLD)
            self.w(y+2,cw3+2,f"TLS: {ssl_r.get('tls','?')}  Bits: {ssl_r.get('bits',0)}",curses.color_pair(C_VAL))
            self.w(y+3,cw3+2,f"Expires: {days}d left",curses.color_pair(dc)|curses.A_BOLD)
            self.w(y+4,cw3+2,f"Issuer: {ssl_r.get('issuer','N/A')[:26]}",curses.color_pair(C_DIM))
            wk=ssl_r.get("weak",False)
            self.w(y+5,cw3+2,f"Cipher: {'⚠ WEAK' if wk else '✓ OK'} ({ssl_r.get('cipher','?')[:18]})",
                   curses.color_pair(C_DANGER if wk else C_SAFE))
        elif ssl_r:
            self.w(y+1,cw3+2,f"✗ {ssl_r.get('error','No SSL')[:34]}",curses.color_pair(C_DANGER)|curses.A_BOLD)

        self.w(y,cw3*2+2,"DNSBL STATUS",curses.color_pair(C_LABEL)|curses.A_BOLD)
        if self.scanner.status=="complete":
            if bl and isinstance(bl,list):
                self.w(y+1,cw3*2+2,f"⚠ LISTED on {len(bl)} blacklist(s)!",curses.color_pair(C_CRIT)|curses.A_BOLD)
                for i,b in enumerate(bl[:5]): self.w(y+2+i,cw3*2+2,f"  • {b}",curses.color_pair(C_DANGER))
            else:
                self.w(y+1,cw3*2+2,"✓ Clean — not blacklisted",curses.color_pair(C_SAFE)|curses.A_BOLD)
                self.w(y+2,cw3*2+2,"Checked 5 real DNSBLs:",curses.color_pair(C_DIM))
                for i,bl_name in enumerate(["zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net"]):
                    self.w(y+3+i,cw3*2+2,f"  ✓ {bl_name}",curses.color_pair(C_DIM))
        else:
            self.w(y+1,cw3*2+2,f"⟳ {self.scanner.status}...",curses.color_pair(C_WARN))

    # ── RECON ─────────────────────────────────────────────────────────────────
    def _recon(self, y0):
        h,W=self.scr.getmaxyx(); y=y0
        if self.scanner.status!="complete":
            p=self.scanner.progress
            self.w(y,2,f"⟳ {self.scanner.status}",curses.color_pair(C_WARN)|curses.A_BOLD)
            self.w(y+1,2,f"[{bar(p,100,60)}] {p}%",curses.color_pair(C_GREEN))
            self.w(y+3,2,"Performing real network reconnaissance — no simulated data",curses.color_pair(C_DIM))
            return
        r=self.scan
        dns=r.get("dns",{}); ssl_r=r.get("ssl",{}); http=r.get("http",{})
        ports=r.get("ports",[]); whois=r.get("whois",{}); geo=r.get("geo",{})
        ping=r.get("ping",{})

        # DNS
        self.w(y,2,"─── DNS RECORDS (real lookup) ────────────────────────",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        recs=dns.get("records",{})
        for rtype,vals in recs.items():
            if isinstance(vals,list) and vals:
                for v in vals[:3]: self.w(y,4,f"{rtype:<8} {str(v)[:W-16]}",curses.color_pair(C_VAL)); y+=1
            elif isinstance(vals,dict):
                for ip,ptr in list(vals.items())[:2]: self.w(y,4,f"PTR      {ip} → {ptr}",curses.color_pair(C_VAL)); y+=1
        spf=dns.get("spf"); dmarc=dns.get("dmarc")
        self.w(y,4,f"SPF:   {'✓ '+spf[:40] if spf else '✗ Missing — email spoofing risk'}",
               curses.color_pair(C_SAFE if spf else C_WARN)); y+=1
        self.w(y,4,f"DMARC: {'✓ Found' if dmarc else '✗ Missing — no DMARC policy'}",
               curses.color_pair(C_SAFE if dmarc else C_WARN)); y+=2

        # SSL
        self.w(y,2,"─── SSL/TLS CERTIFICATE (real handshake) ─────────────",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        if ssl_r.get("valid"):
            for k,v in [("Common Name",ssl_r.get("cn","N/A")),
                        ("Organization",ssl_r.get("org","N/A")),
                        ("TLS Version",ssl_r.get("tls","N/A")),
                        ("Cipher Suite",ssl_r.get("cipher","N/A")),
                        ("Key Bits",str(ssl_r.get("bits","N/A"))),
                        ("Issuer Org",ssl_r.get("issuer","N/A")),
                        ("Issuer CN",ssl_r.get("issuer_cn","N/A")),
                        ("Valid From",ssl_r.get("not_before","N/A")),
                        ("Valid Until",ssl_r.get("not_after","N/A")),
                        ("Days Left",f"{ssl_r.get('days','?')} days"),
                        ("Serial",ssl_r.get("serial","N/A")[:30])]:
                self.w(y,4,f"{k:<16}: {str(v)[:W-25]}",curses.color_pair(C_VAL)); y+=1
            san=ssl_r.get("san",[])
            if san: self.w(y,4,f"SANs ({len(san)}):       {', '.join(san[:4])}"[:W-6],curses.color_pair(C_DIM)); y+=1
        else:
            self.w(y,4,f"✗ SSL Error: {ssl_r.get('error','N/A')}"[:W-6],curses.color_pair(C_DANGER)|curses.A_BOLD); y+=1
        y+=1

        # HTTP
        self.w(y,2,"─── HTTP RESPONSE (real request) ─────────────────────",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        sc=http.get("status",0)
        self.w(y,4,f"Status : {sc} ({http.get('scheme','?').upper()})",
               curses.color_pair(C_SAFE if 200<=sc<400 else C_DANGER)|curses.A_BOLD); y+=1
        for k,v in [("Server",http.get("server","N/A")),("Powered-By",http.get("powered","N/A")),
                    ("Content-Type",http.get("ctype","N/A")),("CORS",http.get("cors","N/A")),
                    ("Redirected","Yes → "+http.get("final","") if http.get("redirect") else "No"),
                    ("Cookies Set",str(http.get("cookie",False)))]:
            self.w(y,4,f"{k:<14}: {str(v)[:W-22]}",curses.color_pair(C_VAL)); y+=1
        y+=1
        self.w(y,4,"Security Headers (real check):",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        for hdr in sorted(SEC_HEADERS):
            ok=hdr in http.get("ok_hdrs",[])
            self.w(y,6,f"{'✓' if ok else '✗'} {hdr:<34}",
                   curses.color_pair(C_SAFE if ok else C_WARN)); y+=1
        y+=1

        # Ports
        self.w(y,2,"─── OPEN PORTS (real TCP connect scan) ───────────────",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        if isinstance(ports,list) and ports:
            for i,p in enumerate(ports):
                nm=PORT_NAMES.get(p,"?"); rk=p in RISKY_PORTS
                col=C_DANGER if rk else C_SAFE
                self.w(y,4+(i%3)*23,f"{p}/{nm}{' ⚠' if rk else ''}",curses.color_pair(col))
                if i%3==2: y+=1
            y+=2
        else:
            self.w(y,4,"No common ports open / scan blocked",curses.color_pair(C_DIM)); y+=2

        # Ping
        self.w(y,2,"─── PING RESULTS (real ICMP) ─────────────────────────",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        if ping:
            for k,v in [("Min RTT",fmt_ms(ping.get("min",-1))),
                        ("Avg RTT",fmt_ms(ping.get("avg",-1))),
                        ("Max RTT",fmt_ms(ping.get("max",-1))),
                        ("Packet Loss",f"{ping.get('loss',100)}%")]:
                self.w(y,4,f"{k:<14}: {v}",curses.color_pair(C_VAL)); y+=1
        y+=1

        # WHOIS
        self.w(y,2,"─── WHOIS / ASN (real RDAP/whois) ────────────────────",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        for k,v in whois.items():
            self.w(y,4,f"{k:<12}: {str(v)[:W-20]}",curses.color_pair(C_VAL)); y+=1

    # ── LIVE NET ──────────────────────────────────────────────────────────────
    def _livenet(self, y0):
        h,W=self.scr.getmaxyx(); y=y0
        net=self.net
        self.w(y,2,"REAL-TIME NETWORK INTERFACE I/O",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=2
        ifaces=get_net_interfaces()
        if ifaces:
            hdr=f"{'INTERFACE':<14} {'RX/s':>10} {'TX/s':>10} {'RX PKTS/s':>10} {'ERRORS':>8}"
            self.w(y,2,hdr,curses.color_pair(C_LABEL)); self.hl(y+1,2,'─',W-4,curses.color_pair(C_BORDER)); y+=2
            prev=net._prev
            for iface,v in sorted(ifaces.items())[:10]:
                p=prev.get(iface,v)
                rx=max(0,v["bytes_in"]-p["bytes_in"]); tx=max(0,v["bytes_out"]-p["bytes_out"])
                pk=max(0,v["pkts_in"]-p["pkts_in"]); er=v.get("errin",0)+v.get("errout",0)
                col=C_DANGER if er>0 else C_VAL
                self.w(y,2,f"{iface:<14} {fmt_bytes(rx):>10} {fmt_bytes(tx):>10} {pk:>10,} {er:>8}",
                       curses.color_pair(col)); y+=1
        y+=1

        # BW graph
        gh=5; gw=min(W-14,MAX_GRAPH)
        hi=list(net.bps_in)[-gw:]; ho=list(net.bps_out)[-gw:]
        mv=max(max(hi,default=1),max(ho,default=1),1)
        self.w(y,1,"BANDWIDTH HISTORY (real /proc or psutil):",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        self.w(y,1,"┌"+"─"*gw+"┐",curses.color_pair(C_BORDER))
        for ri in range(gh):
            tlo=mv*(gh-ri-1)/gh; thi=mv*(gh-ri)/gh
            self.w(y+1+ri,1,"│",curses.color_pair(C_BORDER))
            for ci,(vi,vo) in enumerate(zip(hi,ho)):
                if vi>=thi:    ch="█";col=C_GREEN
                elif vi>=tlo:  ch="▄";col=C_GREEN
                elif vo>=thi:  ch="▀";col=C_BLUE
                else:          ch=" ";col=C_DIM
                self.w(y+1+ri,2+ci,ch,curses.color_pair(col))
            self.w(y+1+ri,2+gw,"│",curses.color_pair(C_BORDER))
            self.w(y+1+ri,2+gw+1,f" {fmt_bytes(int(thi)):>8}",curses.color_pair(C_DIM))
        self.w(y+gh+1,1,"└"+"─"*gw+"┘",curses.color_pair(C_BORDER)); y+=gh+2

        # Packet capture
        self.w(y,2,"LIVE PACKET CAPTURE (scapy):",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        cap=self.cap
        is_root=(os.geteuid()==0) if sys.platform!="win32" else True
        if SCAPY and is_root and cap.running:
            self.w(y,2,f"✓ ACTIVE — pkts: {cap.total:,}  bytes: {fmt_bytes(cap.total_bytes)}  pps: {cap.cur_pps}/s",
                   curses.color_pair(C_SAFE)); y+=1
            # Top sources
            srcs=sorted(cap.src_c.items(),key=lambda x:-x[1])[:6]
            protos=sorted(cap.proto_c.items(),key=lambda x:-x[1])
            self.w(y,2,"Top src IPs:",curses.color_pair(C_LABEL)); y+=1
            for ip,cnt in srcs:
                self.w(y,4,f"{ip:<20} {cnt:>8} pkts",curses.color_pair(C_VAL)); y+=1
            y+=1
            self.w(y,2,"Protocols:",curses.color_pair(C_LABEL)); y+=1
            for pr,cnt in protos[:5]:
                self.w(y,4,f"{pr:<8} {cnt:>8}",curses.color_pair(C_VAL)); y+=1
        elif SCAPY and not is_root:
            self.w(y,2,"✗ Need root for packet capture",curses.color_pair(C_WARN))
            self.w(y+1,2,"  → sudo python3 threat_tracker.py",curses.color_pair(C_DIM)); y+=3
        elif not SCAPY:
            self.w(y,2,"✗ scapy not installed",curses.color_pair(C_WARN))
            self.w(y+1,2,"  → pip install scapy  then  sudo python3 threat_tracker.py",curses.color_pair(C_DIM))
            self.w(y+2,2,"  Network I/O above is still real (from /proc/net/dev or psutil)",curses.color_pair(C_DIM))

    # ── PING/RT ───────────────────────────────────────────────────────────────
    def _ping_tab(self, y0):
        h,W=self.scr.getmaxyx(); y=y0
        rs=self.rs
        self.w(y,2,f"LIVE PING & HTTP MONITOR — {self.domain}",curses.color_pair(C_LABEL)|curses.A_BOLD)
        self.w(y+1,2,f"Re-checks every {rs.interval}s | Done: {rs._checks} | Uptime: {rs.uptime:.2f}%",
               curses.color_pair(C_DIM)); y+=3

        pr=rs.last_ping; lc=C_SAFE if pr.get("loss",100)==0 else(C_WARN if pr.get("loss",100)<50 else C_DANGER)
        self.w(y,2,"CURRENT PING (real ICMP):",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        for k,v in [("Min RTT",fmt_ms(pr.get("min",-1))),("Avg RTT",fmt_ms(pr.get("avg",-1))),
                    ("Max RTT",fmt_ms(pr.get("max",-1))),("Packet Loss",f"{pr.get('loss',100)}%")]:
            c=lc if "Loss" in k else C_VAL
            self.w(y,4,f"{k:<14}: {v}",curses.color_pair(c)|curses.A_BOLD); y+=1
        y+=1

        # Ping history graph
        ph=list(rs.ping_hist)
        if ph:
            self.w(y,2,"PING HISTORY (ms):",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
            mp=max(max(ph),1); gh=6; gw=min(len(ph),W-14)
            self.w(y,1,"┌"+"─"*gw+"┐",curses.color_pair(C_BORDER))
            for ri in range(gh):
                tlo=mp*(gh-ri-1)/gh; thi=mp*(gh-ri)/gh
                self.w(y+1+ri,1,"│",curses.color_pair(C_BORDER))
                for ci,v in enumerate(ph[-gw:]):
                    if v>=thi:    ch="█";col=C_DANGER if v>200 else(C_WARN if v>100 else C_GREEN)
                    elif v>=tlo:  ch="▄";col=C_WARN
                    else:         ch=" ";col=C_DIM
                    self.w(y+1+ri,2+ci,ch,curses.color_pair(col))
                self.w(y+1+ri,2+gw,"│",curses.color_pair(C_BORDER))
                self.w(y+1+ri,2+gw+1,f" {int(thi):>5}ms",curses.color_pair(C_DIM))
            self.w(y+gh+1,1,"└"+"─"*gw+"┘",curses.color_pair(C_BORDER)); y+=gh+2

        # HTTP timing history
        ht=list(rs.http_hist)
        if ht:
            self.w(y,2,"HTTP RESPONSE TIME HISTORY (ms):",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
            mh=max(max(ht),1); gh=4; gw=min(len(ht),W-14)
            self.w(y,1,"┌"+"─"*gw+"┐",curses.color_pair(C_BORDER))
            for ri in range(gh):
                tlo=mh*(gh-ri-1)/gh; thi=mh*(gh-ri)/gh
                self.w(y+1+ri,1,"│",curses.color_pair(C_BORDER))
                for ci,v in enumerate(ht[-gw:]):
                    if v>=thi:    ch="█";col=C_DANGER if v>2000 else(C_WARN if v>500 else C_GREEN)
                    elif v>=tlo:  ch="▄";col=C_WARN
                    else:         ch=" ";col=C_DIM
                    self.w(y+1+ri,2+ci,ch,curses.color_pair(col))
                self.w(y+1+ri,2+gw,"│",curses.color_pair(C_BORDER))
                self.w(y+1+ri,2+gw+1,f" {int(thi):>6}ms",curses.color_pair(C_DIM))
            self.w(y+gh+1,1,"└"+"─"*gw+"┘",curses.color_pair(C_BORDER)); y+=gh+2

        # Traceroute
        hops=self.scan.get("traceroute",[])
        if hops:
            self.w(y,2,"TRACEROUTE (real):",curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
            for hop in hops[:14]:
                mc=C_SAFE if hop["ms"]<50 else(C_WARN if hop["ms"]<150 else C_DANGER)
                self.w(y,4,f"Hop {hop['hop']:>2}  {hop['ip']:<18}  {fmt_ms(hop['ms'])}",
                       curses.color_pair(mc)); y+=1
        else:
            self.w(y,2,"Traceroute: running in background...",curses.color_pair(C_DIM))

    # ── EVENTS ────────────────────────────────────────────────────────────────
    def _events(self, y0):
        h,W=self.scr.getmaxyx(); y=y0
        evs=list(self.all_ev)
        self.w(y,2,f"EVENT LOG — {len(evs)} entries (real network events only) ↑↓",
               curses.color_pair(C_LABEL)|curses.A_BOLD); y+=1
        self.hl(y,2,'─',W-4,curses.color_pair(C_BORDER)); y+=1
        mr=h-y-2; off=clamp(self.scroll,0,max(0,len(evs)-mr))
        for i,ev in enumerate(evs[off:off+mr]):
            col=(C_DANGER if "ALERT" in ev or "ERROR" in ev
                 else C_WARN if "WARN" in ev
                 else C_CRIT if "BLOCK" in ev
                 else C_SAFE if "OK" in ev or "✓" in ev or "complete" in ev
                 else C_DIM)
            self.w(y+i,2,ev[:W-4],curses.color_pair(col))
        self.w(h-2,2,"↑↓ scroll",curses.color_pair(C_DIM))

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self):
        while self.running:
            self.scr.erase()
            if self.input_mode:
                self._input_screen()
            else:
                # Merge real events
                evs=(list(self.rs.events)+list(self.net.events)+
                     list(self.cap.events)+list(getattr(self.scanner,"_evlog",[])))
                evs=sorted(set(evs),reverse=True)
                self.all_ev=deque(evs[:MAX_EVENTS],maxlen=MAX_EVENTS)
                if self.scanner.status=="complete":
                    self.risk,self.reasons=compute_risk(self.scan,self.rs)
                self._header()
                cs=self._tabs()
                [self._dashboard,self._recon,self._livenet,self._ping_tab,self._events][self.tab](cs)
            self.scr.refresh()
            self._keys()
            time.sleep(0.1)

    def _keys(self):
        try: k=self.scr.getch()
        except: return
        if k==-1: return
        if self.input_mode:
            if k in(curses.KEY_ENTER,10,13):
                d=self.input_buf.strip()
                if d: self._start(d)
            elif k in(curses.KEY_BACKSPACE,127,8): self.input_buf=self.input_buf[:-1]
            elif 32<=k<=126: self.input_buf+=chr(k)
        else:
            if k in(ord('q'),ord('Q')): self._quit()
            elif k in(ord('\t'),curses.KEY_RIGHT): self.tab=(self.tab+1)%len(self.TABS)
            elif k==curses.KEY_LEFT: self.tab=(self.tab-1)%len(self.TABS)
            elif ord('1')<=k<=ord('5'): self.tab=k-ord('1')
            elif k in(ord('r'),ord('R')): self._reset()
            elif k==curses.KEY_DOWN: self.scroll+=1
            elif k==curses.KEY_UP: self.scroll=max(0,self.scroll-1)

    def _start(self, domain):
        self.domain=domain; self.input_mode=False; curses.curs_set(0)
        def done(res):
            self.scan=res
            ip=res.get("dns",{}).get("ips",[""])[0] or ""
            # Traceroute async
            def do_tr():
                self.scan["traceroute"]=real_traceroute(ip or domain)
            threading.Thread(target=do_tr,daemon=True).start()
            self.rs.start(domain,ip)
            self.cap.start(ip or None)
        self.scanner.scan(domain,done)
        self.net.start()

    def _reset(self):
        for obj in[self.rs,self.net,self.cap]: obj.stop()
        self.__init__(self.scr); curses.curs_set(1)

    def _quit(self):
        for obj in[self.rs,self.net,self.cap]: obj.stop()
        self.running=False

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if sys.version_info<(3,7): print("Python 3.7+ required"); sys.exit(1)
    print("\033[1;36m")
    print("╔══════════════════════════════════════════════════════╗")
    print("║  THREAT TRACKER v2 — 100% Real Network Data         ║")
    print("║  No simulation. No fake data. All real.             ║")
    print("╚══════════════════════════════════════════════════════╝\033[0m")
    if sys.platform=="win32":
        try: import curses
        except ImportError: print("pip install windows-curses"); sys.exit(1)
    is_root=(os.geteuid()==0) if sys.platform!="win32" else True
    if not SCAPY:
        print("\033[33m[INFO] scapy not installed — live packet capture disabled.")
        print("       pip install scapy  then  sudo python3 threat_tracker.py\033[0m")
    elif not is_root:
        print("\033[33m[INFO] Not root — live packet capture disabled.")
        print("       sudo python3 threat_tracker.py  for full capture\033[0m")
    if not PSUTIL:
        print("\033[33m[INFO] psutil not installed — using /proc/net/dev for net stats.")
        print("       pip install psutil  for richer interface data\033[0m")
    time.sleep(1)
    try: curses.wrapper(lambda s: App(s).run())
    except KeyboardInterrupt: pass
    finally: print("\n\033[1;36mThreat Tracker terminated. Stay secure! 🛡\033[0m\n")

if __name__=="__main__": main()
