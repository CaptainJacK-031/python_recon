#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
passive_recon.py - passive OSINT reconnaissance for a domain, URL or IP address.

The scanner only talks to third-party public data sources (DNS-over-HTTPS
resolvers, RDAP registries, certificate-transparency logs, web archives,
passive-DNS and internet-scan indexes, routing data, threat-intel feeds and,
optionally, API-key services). It never opens a connection to the target's own
servers.

    python3 passive_recon.py example.com
    python3 passive_recon.py https://app.example.com/login
    python3 passive_recon.py 203.0.113.10
    python3 passive_recon.py example.com -o out --only dns,rdap,crtsh,otx
    python3 passive_recon.py --list-modules

Python 3.8+, standard library only.

Optional API keys (environment variables, or KEY=VALUE lines via --keys-file):
    VT_API_KEY  SECURITYTRAILS_API_KEY  SHODAN_API_KEY  GITHUB_TOKEN
    FULLHUNT_API_KEY  CHAOS_API_KEY  URLSCAN_API_KEY  OTX_API_KEY
    CERTSPOTTER_API_KEY  GREYNOISE_API_KEY
    BRAVE_API_KEY | SERPAPI_KEY | GOOGLE_CSE_KEY + GOOGLE_CSE_CX  (automated dorking)

Use it for assets you own, authorised assessments, bug-bounty scope and public
research. It collects infrastructure- and organisation-level data, not profiles
of individuals.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import html as htmllib
import http.client
import ipaddress
import json
import os
import random
import re
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import Counter, defaultdict

__version__ = "1.0.0"
UA = "Mozilla/5.0 (compatible; passive-recon/%s)" % __version__
MAX_BODY = 96 * 1024 * 1024

HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")
EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,253}\.[a-z]{2,24}$")
SLD_WORDS = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "mil", "sch", "gob", "nom", "ltd", "plc"}
SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_TLS = threading.local()


# ============================================================================
# small helpers
# ============================================================================
def short(s, n=120):
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def norm_host(h):
    return (h or "").strip().lower().rstrip(".")


def registrable(host):
    """Heuristic registrable domain (no public-suffix list; use --exact to override)."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in SLD_WORDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_dt(s):
    if not s:
        return None
    s = str(s).strip()
    for cand in (s.replace("Z", "+00:00"), s[:19], s[:10]):
        try:
            d = dt.datetime.fromisoformat(cand)
            return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def ts_date(ts):
    ts = str(ts or "")
    return "%s-%s-%s" % (ts[:4], ts[4:6], ts[6:8]) if len(ts) >= 8 and ts[:8].isdigit() else ts


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def quote(s):
    return urllib.parse.quote(str(s), safe="")


def match_table(name, table):
    n = (name or "").lower()
    for needle, label in table:
        if needle in n:
            return label
    return None


# ============================================================================
# knowledge tables (used to turn raw records into readable intelligence)
# ============================================================================
NS_PROVIDERS = [
    ("ns.cloudflare.com", "Cloudflare DNS"), ("awsdns", "Amazon Route 53"), ("azure-dns", "Azure DNS"),
    ("ns-cloud-", "Google Cloud DNS"), ("googledomains.com", "Google Domains DNS"),
    ("domaincontrol.com", "GoDaddy DNS"), ("registrar-servers.com", "Namecheap DNS"), ("nsone.net", "NS1"),
    ("dnsmadeeasy.com", "DNS Made Easy"), ("ultradns", "UltraDNS"), ("akam.net", "Akamai Edge DNS"),
    ("dynect.net", "Oracle Dyn"), ("digitalocean.com", "DigitalOcean DNS"), ("linode.com", "Linode DNS"),
    ("hetzner", "Hetzner DNS"), ("ovh.net", "OVH DNS"), ("gandi.net", "Gandi"), ("wixdns.net", "Wix"),
    ("squarespacedns.com", "Squarespace"), ("vercel-dns.com", "Vercel DNS"), ("he.net", "Hurricane Electric DNS"),
    ("dnsimple.com", "DNSimple"), ("worldnic.com", "Network Solutions"), ("name-services.com", "Enom"),
    ("markmonitor.com", "MarkMonitor"), ("cscdns.net", "CSC Global DNS"), ("alidns.com", "Alibaba Cloud DNS"),
    ("dnspod.net", "Tencent DNSPod"), ("bluehost.com", "Bluehost"), ("hostgator.com", "HostGator"),
    ("siteground", "SiteGround"), ("ui-dns", "IONOS"), ("dreamhost.com", "DreamHost"), ("porkbun.com", "Porkbun"),
]
MX_PROVIDERS = [
    ("aspmx.l.google.com", "Google Workspace / Gmail"), ("googlemail.com", "Google Workspace / Gmail"),
    ("google.com", "Google Workspace / Gmail"), ("mail.protection.outlook.com", "Microsoft 365 (Exchange Online)"),
    ("outlook.com", "Microsoft Outlook / 365"), ("pphosted.com", "Proofpoint"), ("ppe-hosted.com", "Proofpoint Essentials"),
    ("mimecast", "Mimecast"), ("zoho.", "Zoho Mail"), ("protonmail.ch", "Proton Mail"),
    ("messagingengine.com", "Fastmail"), ("secureserver.net", "GoDaddy Email"), ("emailsrvr.com", "Rackspace Email"),
    ("barracudanetworks.com", "Barracuda"), ("mailgun.org", "Mailgun"), ("icloud.com", "Apple iCloud Mail"),
    ("yandex.net", "Yandex Mail"), ("qq.com", "Tencent Mail"), ("mx.cloudflare.net", "Cloudflare Email Routing"),
    ("improvmx.com", "ImprovMX"), ("forwardemail.net", "Forward Email"), ("titan.email", "Titan Email"),
    ("privateemail.com", "Namecheap Private Email"), ("ovh.net", "OVH Mail"), ("ionos", "IONOS Mail"),
    ("1and1", "IONOS Mail"), ("sophos", "Sophos Email"), ("trendmicro", "Trend Micro Email Security"),
    ("iphmx.com", "Cisco Email Security"), ("messagelabs.com", "Symantec/Broadcom Email Security"),
]
SPF_VENDORS = [
    ("_spf.google.com", "Google Workspace"), ("spf.protection.outlook.com", "Microsoft 365"),
    ("sendgrid.net", "SendGrid"), ("mailgun.org", "Mailgun"), ("amazonses.com", "Amazon SES"),
    ("mandrillapp.com", "Mailchimp Transactional (Mandrill)"), ("servers.mcsv.net", "Mailchimp"),
    ("mailchimp", "Mailchimp"), ("spf.mtasv.net", "Postmark"), ("zendesk.com", "Zendesk"),
    ("freshdesk.com", "Freshdesk"), ("salesforce.com", "Salesforce"), ("hubspot", "HubSpot"),
    ("helpscoutemail.com", "Help Scout"), ("sparkpostmail.com", "SparkPost"), ("mailjet.com", "Mailjet"),
    ("sendinblue.com", "Brevo (Sendinblue)"), ("zoho.", "Zoho"), ("mimecast", "Mimecast"),
    ("pphosted.com", "Proofpoint"), ("secureserver.net", "GoDaddy"), ("emailsrvr.com", "Rackspace"),
    ("icloud.com", "Apple iCloud"), ("messagingengine.com", "Fastmail"), ("protonmail.ch", "Proton Mail"),
    ("customeriomail.com", "Customer.io"), ("intercom", "Intercom"), ("atlassian.net", "Atlassian"),
    ("mktomail.com", "Marketo"), ("pardot", "Salesforce Pardot"), ("eloqua", "Oracle Eloqua"),
    ("createsend.com", "Campaign Monitor"), ("klaviyo", "Klaviyo"), ("constantcontact", "Constant Contact"),
    ("shopify", "Shopify"), ("stripe.com", "Stripe"),
]
DKIM_VENDORS = [
    ("sendgrid", "SendGrid"), ("mailgun", "Mailgun"), ("amazonses", "Amazon SES"), ("mandrillapp", "Mandrill"),
    ("mcsv", "Mailchimp"), ("zoho", "Zoho"), ("protonmail", "Proton Mail"), ("messagingengine", "Fastmail"),
    ("outlook.com", "Microsoft 365"), ("onmicrosoft", "Microsoft 365"), ("google", "Google Workspace"),
    ("postmarkapp", "Postmark"), ("hubspot", "HubSpot"), ("sendinblue", "Brevo"), ("mailjet", "Mailjet"),
    ("sparkpost", "SparkPost"), ("mimecast", "Mimecast"), ("salesforce", "Salesforce"), ("zendesk", "Zendesk"),
]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim",
                  "smtp", "mandrill", "zoho", "pm", "mxvault", "protonmail", "protonmail2", "protonmail3",
                  "fm1", "fm2", "fm3", "cm", "sig1"]
SELECTOR_GUESS = {"google": "Google Workspace", "selector1": "Microsoft 365", "selector2": "Microsoft 365",
                  "protonmail": "Proton Mail", "protonmail2": "Proton Mail", "protonmail3": "Proton Mail",
                  "fm1": "Fastmail", "fm2": "Fastmail", "fm3": "Fastmail", "mandrill": "Mandrill", "zoho": "Zoho"}
DMARC_VENDORS = [("dmarcian", "dmarcian"), ("agari", "Agari"), ("valimail", "Valimail"), ("ondmarc", "Red Sift OnDMARC"),
                 ("dmarc.postmarkapp.com", "Postmark DMARC"), ("easydmarc", "EasyDMARC"), ("uriports", "URIports"),
                 ("proofpoint", "Proofpoint"), ("mimecast", "Mimecast"), ("dmarcanalyzer", "DMARC Analyzer"),
                 ("rua.powerdmarc", "PowerDMARC"), ("google.com", "Google Postmaster")]
TXT_VERIFY = [(re.compile(p, re.I), n) for p, n in [
    (r"^google-site-verification=", "Google (Search Console / Workspace)"),
    (r"^MS=ms\d+", "Microsoft 365"), (r"^ms-domain-verification=", "Microsoft (domain verification)"),
    (r"^facebook-domain-verification=", "Meta (Facebook) Business"), (r"^atlassian-domain-verification=", "Atlassian"),
    (r"^docusign=", "DocuSign"), (r"^adobe-idp-site-verification=", "Adobe"), (r"^apple-domain-verification=", "Apple"),
    (r"^stripe-verification=", "Stripe"), (r"^(zoom-domain-verification=|ZOOM_verify_)", "Zoom"),
    (r"^slack-domain-verification=", "Slack"), (r"^dropbox-domain-verification=", "Dropbox"),
    (r"^onetrust-domain-verification=", "OneTrust"), (r"^globalsign-domain-verification=", "GlobalSign"),
    (r"^(_github-challenge-|github-verification=)", "GitHub"), (r"^miro-verification=", "Miro"),
    (r"^notion-domain-verification=", "Notion"), (r"^have-i-been-pwned-verification=", "Have I Been Pwned"),
    (r"^cisco-ci-domain-verification=", "Cisco"), (r"^webexdomainverification", "Webex"),
    (r"^status-page-domain-verification=", "Atlassian Statuspage"), (r"^postman-domain-verification=", "Postman"),
    (r"^smartsheet-site-validation=", "Smartsheet"), (r"^airtable-verification=", "Airtable"),
    (r"^canva-site-verification=", "Canva"), (r"^segment-site-verification=", "Segment"),
    (r"^bugcrowd-verification=", "Bugcrowd"), (r"^hackerone-site-verification=", "HackerOne"),
    (r"^yandex-verification:", "Yandex"), (r"^baidu-site-verification", "Baidu"),
    (r"^pinterest-site-verification=", "Pinterest"), (r"^TeamViewer-verification", "TeamViewer"),
    (r"^amazonses:", "Amazon SES"), (r"^citrix-verification-code=", "Citrix"), (r"^mongodb-site-verification=", "MongoDB"),
    (r"^openai-domain-verification=", "OpenAI"), (r"^anthropic-domain-verification", "Anthropic"),
    (r"^docker-verification=", "Docker"), (r"^figma", "Figma"), (r"^cloudflare-verify", "Cloudflare"),
    (r"^snowflake", "Snowflake"), (r"^sophos-domain-verification=", "Sophos"), (r"^workplace-domain-verification=", "Meta Workplace"),
]]
# (needle in CNAME target, service label, takeover-prone if the target is left dangling)
CNAME_SERVICES = [
    ("cloudfront.net", "Amazon CloudFront (CDN)", True), ("elasticbeanstalk.com", "AWS Elastic Beanstalk", True),
    ("s3-website", "AWS S3 static website", True), ("s3.amazonaws.com", "AWS S3", True),
    ("elb.amazonaws.com", "AWS load balancer", False), ("awsglobalaccelerator.com", "AWS Global Accelerator", False),
    ("azurewebsites.net", "Azure App Service", True), ("azureedge.net", "Azure CDN", True),
    ("azurefd.net", "Azure Front Door", True), ("trafficmanager.net", "Azure Traffic Manager", True),
    ("cloudapp.net", "Azure Cloud Service", True), ("cloudapp.azure.com", "Azure VM public DNS", True),
    ("blob.core.windows.net", "Azure Blob Storage", True), ("herokuapp.com", "Heroku", True),
    ("herokudns.com", "Heroku", True), ("github.io", "GitHub Pages", True), ("gitlab.io", "GitLab Pages", True),
    ("bitbucket.io", "Bitbucket Pages", True), ("netlify.app", "Netlify", True), ("netlify.com", "Netlify", True),
    ("vercel.app", "Vercel", True), ("vercel-dns.com", "Vercel", False), ("pages.dev", "Cloudflare Pages", False),
    ("workers.dev", "Cloudflare Workers", False), ("fastly.net", "Fastly (CDN)", True),
    ("edgekey.net", "Akamai (CDN)", False), ("edgesuite.net", "Akamai (CDN)", False), ("akamaiedge.net", "Akamai (CDN)", False),
    ("incapdns.net", "Imperva Incapsula", False), ("sucuri.net", "Sucuri", False), ("wpengine.com", "WP Engine", True),
    ("myshopify.com", "Shopify", True), ("wordpress.com", "WordPress.com", True), ("ghost.io", "Ghost(Pro)", True),
    ("squarespace.com", "Squarespace", False), ("wixdns.net", "Wix", False), ("zendesk.com", "Zendesk", True),
    ("freshdesk.com", "Freshdesk", False), ("statuspage.io", "Atlassian Statuspage", True), ("readme.io", "ReadMe", True),
    ("helpscoutdocs.com", "Help Scout Docs", True), ("unbouncepages.com", "Unbounce", True), ("hubspot", "HubSpot", False),
    ("pantheonsite.io", "Pantheon", True), ("surge.sh", "Surge.sh", True), ("firebaseapp.com", "Firebase Hosting", False),
    ("web.app", "Firebase Hosting", False), ("appspot.com", "Google App Engine", False), ("run.app", "Google Cloud Run", False),
    ("storage.googleapis.com", "Google Cloud Storage", True), ("ghs.googlehosted.com", "Google Sites/Blogger", False),
    ("webflow.io", "Webflow", True), ("cargocollective.com", "Cargo", True), ("tumblr.com", "Tumblr", True),
    ("uservoice.com", "UserVoice", True), ("teamwork.com", "Teamwork", True), ("strikingly.com", "Strikingly", True),
    ("readthedocs.io", "Read the Docs", False), ("fly.dev", "Fly.io", False), ("onrender.com", "Render", False),
    ("digitaloceanspaces.com", "DigitalOcean Spaces", True), ("ngrok.io", "ngrok", True), ("launchrock.com", "Launchrock", True),
    ("cloudflare.net", "Cloudflare", False), ("outlook.com", "Microsoft 365 / Exchange Online", False),
    ("proofpoint", "Proofpoint", False), ("mailgun.org", "Mailgun", False), ("sendgrid.net", "SendGrid", False),
]
BIG_HOSTS = [
    ("cloudflare", "Cloudflare"), ("amazon", "Amazon AWS"), ("aws", "Amazon AWS"), ("google", "Google"),
    ("microsoft", "Microsoft / Azure"), ("azure", "Microsoft / Azure"), ("akamai", "Akamai"), ("fastly", "Fastly"),
    ("digitalocean", "DigitalOcean"), ("ovh", "OVH"), ("hetzner", "Hetzner"), ("linode", "Linode / Akamai"),
    ("vultr", "Vultr"), ("choopa", "Vultr"), ("oracle", "Oracle Cloud"), ("alibaba", "Alibaba Cloud"),
    ("tencent", "Tencent Cloud"), ("incapsula", "Imperva"), ("imperva", "Imperva"), ("sucuri", "Sucuri"),
    ("github", "GitHub"), ("netlify", "Netlify"), ("vercel", "Vercel"), ("godaddy", "GoDaddy"),
    ("namecheap", "Namecheap"), ("rackspace", "Rackspace"), ("ionos", "IONOS"), ("leaseweb", "Leaseweb"),
    ("contabo", "Contabo"), ("scaleway", "Scaleway"), ("heroku", "Heroku"), ("shopify", "Shopify"),
    ("wix", "Wix"), ("squarespace", "Squarespace"), ("automattic", "Automattic / WordPress.com"),
]
HOST_HINTS = [
    ("Non-production", {"dev", "development", "stage", "staging", "stg", "test", "testing", "qa", "uat", "sandbox",
                        "beta", "demo", "preprod", "preview", "canary"}),
    ("Admin / internal / remote access", {"admin", "administrator", "internal", "intranet", "corp", "vpn", "remote",
                                          "rdp", "ssh", "sftp", "portal", "sso", "login", "auth", "idp", "adfs",
                                          "okta", "citrix", "bastion", "jump"}),
    ("DevOps & tooling", {"jenkins", "gitlab", "git", "github", "bitbucket", "jira", "confluence", "grafana", "kibana",
                          "prometheus", "sonar", "sonarqube", "nexus", "artifactory", "ci", "build", "docker",
                          "registry", "k8s", "kubernetes", "argocd", "vault", "consul", "rancher", "harbor", "wiki"}),
    ("Mail & messaging", {"mail", "smtp", "imap", "pop", "pop3", "mx", "webmail", "autodiscover", "exchange", "owa", "email"}),
    ("API & backend", {"api", "gateway", "gw", "graphql", "ws", "rest", "backend", "service", "services", "rpc", "grpc"}),
    ("Data & storage", {"db", "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic", "elasticsearch",
                        "s3", "storage", "backup", "files", "ftp", "cdn", "static", "assets", "media"}),
    ("Monitoring & status", {"status", "monitor", "monitoring", "nagios", "zabbix", "metrics", "logs", "log",
                             "splunk", "elk", "sentry"}),
]
RISKY_PORTS = {23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle DB",
               2049: "NFS", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana",
               5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
URL_CATEGORIES = [(c, re.compile(p, re.I)) for c, p in [
    ("Secrets & config files",
     r"(/\.env(\.[a-z0-9]+)?(\?|$|/)|/\.git(/|$)|/\.svn(/|$)|/\.hg(/|$)|/\.ds_store|wp-config|/config\.(php|json|ya?ml|xml|ini)(\?|$)"
     r"|web\.config|\.htpasswd|\.htaccess|id_rsa|\.(pem|key|p12|pfx|jks|kdbx)(\?|$)|credentials|secrets?\.(json|ya?ml|txt)"
     r"|\.npmrc|docker-compose|/\.aws/|appsettings\.json)"),
    ("Backups & dumps", r"(\.(sql|sqlite3?|db|mdb|bak|backup|old|orig|save|swp|tar|tgz|gz|zip|rar|7z|dump)(\?|$)|/backups?/)"),
    ("Logs & debug endpoints",
     r"(\.log(\?|$)|/logs?/|phpinfo|server-status|server-info|/actuator(/|$)|/_profiler|/telescope|/elmah|/debug(/|$)|trace\.axd)"),
    ("Admin & login panels",
     r"(/admin|/administrator|/wp-admin|/wp-login|/login|/signin|/sign-in|/sso(/|\?|$)|/oauth|/saml|/dashboard|/console(/|$)"
     r"|/manager/|/phpmyadmin|/cpanel|/webmail|/portal(/|$))"),
    ("API & documentation", r"(/api[/-]|/api$|/swagger|/openapi|/api-docs|/graphql|/graphiql|/rest/|\.wsdl|/soap(/|$)|/v[1-9]/)"),
    ("Documents", r"\.(pdf|docx?|xlsx?|pptx?|csv|odt|ods|rtf)(\?|$)"),
    ("Non-production paths", r"(/test/|/dev/|/staging|/uat/|/beta/|/old/|/tmp/|/temp/|/internal/)"),
]]


def match_service(name):
    n = (name or "").lower().rstrip(".")
    for needle, label, prone in CNAME_SERVICES:
        if needle in n:
            return label, prone
    return None, False


def classify_holder(holder):
    h = (holder or "").lower()
    for needle, label in BIG_HOSTS:
        if re.search(r"(^|[^a-z])" + re.escape(needle), h):
            return label
    return None


# ============================================================================
# networking: logging, HTTP client with throttling/retries, DNS-over-HTTPS
# ============================================================================
class SourceError(Exception):
    """A data source failed (network error, HTTP error, bad payload...)."""


SECRET_RE = re.compile(r"(?i)((?:api)?key|token|secret)=([^&\s]+)")


def mask(s):
    return SECRET_RE.sub(r"\1=***", s)


class Logger:
    def __init__(self, quiet=False, verbose=False):
        self.quiet, self.verbose = quiet, verbose
        self._lock = threading.Lock()

    def info(self, msg):
        if not self.quiet:
            with self._lock:
                print(msg, file=sys.stderr, flush=True)

    def debug(self, msg):
        if self.verbose:
            self.info(msg)


def parse_json(body):
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        raise SourceError("response was not valid JSON (blocked or rate-limited?): %s"
                          % short(body[:80].decode("utf-8", "replace"), 80))


class Http:
    DEFAULT_INTERVAL = 0.15
    INTERVALS = {
        "crt.sh": 1.0, "api.certspotter.com": 1.5, "api.hackertarget.com": 1.5, "otx.alienvault.com": 0.6,
        "urlscan.io": 1.0, "web.archive.org": 0.8, "archive.org": 0.8, "index.commoncrawl.org": 1.0,
        "rdap.org": 0.6, "internetdb.shodan.io": 0.4, "ipwho.is": 0.4, "api.greynoise.io": 1.0,
        "stat.ripe.net": 0.25, "www.virustotal.com": 15.5, "api.securitytrails.com": 1.0, "api.shodan.io": 1.1,
        "api.github.com": 6.5, "api.search.brave.com": 1.1, "serpapi.com": 1.0, "www.googleapis.com": 1.0,
        "login.microsoftonline.com": 0.3, "autodiscover-s.outlook.com": 0.5, "jldc.me": 1.0,
        "fullhunt.io": 1.0, "dns.projectdiscovery.io": 1.0, "cloudflare-dns.com": 0.0, "dns.google": 0.0,
    }

    def __init__(self, timeout, proxy, ua, retries, log):
        handlers = [urllib.request.HTTPSHandler(context=ssl.create_default_context())]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self.opener = urllib.request.build_opener(*handlers)
        self.timeout, self.ua, self.retries, self.log = timeout, ua, retries, log
        self.intervals = dict(self.INTERVALS)
        self._next, self._hlocks = {}, {}
        self._glock = threading.Lock()
        self.requests = 0

    def set_interval(self, host, secs):
        self.intervals[host] = secs

    def _throttle(self, host, interval):
        iv = self.intervals.get(host, self.DEFAULT_INTERVAL) if interval is None else interval
        if iv <= 0:
            return
        with self._glock:
            lock = self._hlocks.setdefault(host, threading.Lock())
        with lock:
            wait = self._next.get(host, 0.0) - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._next[host] = time.monotonic() + iv

    @staticmethod
    def _read(resp, max_bytes):
        enc = (resp.headers.get("Content-Encoding") or "").lower()
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS) if "gzip" in enc else None
        out = bytearray()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            if dec is not None:
                try:
                    chunk = dec.decompress(chunk)
                except zlib.error:
                    break
            out += chunk
            if len(out) >= max_bytes:
                break
        return bytes(out)

    def request(self, url, method="GET", headers=None, data=None, timeout=None, retries=None,
                ok_statuses=(200,), max_bytes=MAX_BODY, interval=None):
        host = urllib.parse.urlsplit(url).hostname or ""
        hdrs = {"User-Agent": self.ua, "Accept": "application/json, text/plain, */*", "Accept-Encoding": "gzip"}
        if headers:
            hdrs.update(headers)
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        except ValueError as e:
            raise SourceError("bad URL: %s" % e)
        timeout = timeout or self.timeout
        retries = self.retries if retries is None else retries
        attempt = 0
        while True:
            self._throttle(host, interval)
            self.requests += 1
            self.log.debug("  %s %s" % (method, mask(url)))
            try:
                with self.opener.open(req, timeout=timeout) as resp:
                    status = resp.getcode()
                    body = self._read(resp, max_bytes)
                    hdr = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                status = e.code
                try:
                    body = self._read(e, 2000000)
                except Exception:
                    body = b""
                hdr = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
                if status in ok_statuses:
                    return status, hdr, body
                if status in (429, 500, 502, 503, 504) and attempt < retries:
                    ra = hdr.get("retry-after", "")
                    wait = float(ra) if ra.isdigit() else 2.0 * (2 ** attempt) + random.random()
                    if wait > 45:
                        raise SourceError("rate limited by %s (retry after %ds)" % (host, int(wait)))
                    time.sleep(wait)
                    attempt += 1
                    continue
                if status == 429:
                    raise SourceError("rate limited by %s (HTTP 429)" % host)
                raise SourceError("HTTP %d from %s" % (status, host))
            except (OSError, http.client.HTTPException) as e:
                if attempt < retries:
                    time.sleep(1.5 * (2 ** attempt) + random.random())
                    attempt += 1
                    continue
                raise SourceError("network error talking to %s: %s" % (host, short(getattr(e, "reason", e), 90)))
            if status in ok_statuses:
                return status, hdr, body
            raise SourceError("HTTP %d from %s" % (status, host))

    def get_json(self, url, **kw):
        return parse_json(self.request(url, **kw)[2])

    def get_text(self, url, **kw):
        return self.request(url, **kw)[2].decode("utf-8", "replace")


RTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
             "DS": 43, "DNSKEY": 48, "CAA": 257}
RTYPE_NAME = {v: k for k, v in RTYPE_NUM.items()}


def clean_rdata(t, data):
    data = data.strip()
    if t == "TXT":
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
        if parts:
            return "".join(p.replace('\\"', '"').replace("\\\\", "\\") for p in parts)
        return data.strip('"')
    if t in ("NS", "CNAME", "PTR"):
        return data.rstrip(".").lower()
    if t == "MX":
        bits = data.split(None, 1)
        return "%s %s" % (bits[0], bits[1].rstrip(".").lower()) if len(bits) == 2 else data
    if t == "SOA":
        bits = data.split()
        if len(bits) >= 2:
            bits[0], bits[1] = bits[0].rstrip(".").lower(), bits[1].rstrip(".").lower()
        return " ".join(bits)
    if t == "CAA":
        m = re.match(r"^\\#\s+\d+\s*([0-9a-fA-F\s]*)$", data)
        if m:
            try:
                raw = bytes.fromhex(re.sub(r"\s+", "", m.group(1)))
                tl = raw[1]
                return '%d %s "%s"' % (raw[0], raw[2:2 + tl].decode("ascii", "replace"),
                                       raw[2 + tl:].decode("utf-8", "replace"))
            except (ValueError, IndexError):
                return data
    return data


class DoH:
    """DNS lookups through public DNS-over-HTTPS resolvers (no packets to the target)."""
    PROVIDERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")

    def __init__(self, http):
        self.http, self.cache, self.lock = http, {}, threading.Lock()

    def query(self, name, rtype):
        key = (name.lower().rstrip("."), rtype)
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        err = None
        for base in self.PROVIDERS:
            try:
                url = base + "?" + urllib.parse.urlencode({"name": key[0], "type": rtype})
                _, _, body = self.http.request(url, headers={"Accept": "application/dns-json"}, retries=1, timeout=15)
                j = json.loads(body.decode("utf-8", "replace"))
                out = {"rcode": int(j.get("Status", -1)), "answers": []}
                for a in j.get("Answer") or []:
                    t = RTYPE_NAME.get(a.get("type"), str(a.get("type")))
                    out["answers"].append({"name": str(a.get("name", "")).rstrip(".").lower(), "type": t,
                                           "ttl": a.get("TTL"), "data": clean_rdata(t, str(a.get("data", "")))})
                with self.lock:
                    self.cache[key] = out
                return out
            except (SourceError, ValueError) as e:
                err = e
        raise SourceError("DNS-over-HTTPS lookup failed for %s %s: %s" % (key[0], rtype, short(err, 80)))


# ============================================================================
# target parsing
# ============================================================================
class Target:
    def __init__(self, raw, kind, host, scope, url=None, port=None):
        self.raw, self.kind, self.host, self.scope, self.url, self.port = raw, kind, host, scope, url, port

    @property
    def ip(self):
        return self.host if self.kind == "ip" else None


def parse_target(raw, exact=False):
    s = (raw or "").strip()
    if not s:
        raise ValueError("empty target")
    try:
        ip = ipaddress.ip_address(s.strip("[]"))
        return Target(s, "ip", str(ip), str(ip))
    except ValueError:
        pass
    if "/" in s and "://" not in s and re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", s):
        raise ValueError("CIDR ranges are not supported; pass a single IP, domain or URL")
    url = s if "://" in s else None
    try:
        sp = urllib.parse.urlsplit(s if url else "//" + s)
        host, port = sp.hostname, sp.port
    except ValueError:
        raise ValueError("could not parse target %r" % s)
    if not host:
        raise ValueError("could not find a host name in %r" % s)
    try:
        ip = ipaddress.ip_address(host)
        return Target(s, "ip", str(ip), str(ip), url=url, port=port)
    except ValueError:
        pass
    host = host.strip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid internationalised domain name")
    if "." not in host or not HOST_RE.match(host):
        raise ValueError("%r does not look like a domain name, URL or IP address" % s)
    return Target(s, "domain", host, host if exact else registrable(host), url=url, port=port)


# ============================================================================
# result store
# ============================================================================
class Results:
    def __init__(self, target, max_urls):
        self.t, self.max_urls = target, max_urls
        self.lock = threading.RLock()
        self.hosts, self.ips, self.urls = {}, {}, {}
        self.emails, self.related, self.netblocks = {}, {}, {}
        self.dns, self.whois, self.certs, self.extras = {}, {}, {}, {}
        self.tech, self._tech_seen = [], set()
        self.findings, self._find_seen = [], set()
        self.status = {}
        self.counts = defaultdict(Counter)
        self.dorks = []
        self.urls_dropped = 0

    def in_scope(self, host):
        if self.t.kind == "ip":
            return True
        return host == self.t.scope or host.endswith("." + self.t.scope)

    def add_host(self, name, source):
        h = norm_host(name)
        if h.startswith("*."):
            h = h[2:]
        if not h or not HOST_RE.match(h) or is_ip(h) or not self.in_scope(h):
            return False
        with self.lock:
            rec = self.hosts.get(h)
            if rec is None:
                rec = self.hosts[h] = {"sources": set(), "ips": set(), "cnames": [], "resolves": None, "rcode": None}
                self.counts[source]["hosts"] += 1
            rec["sources"].add(source)
        return True

    def add_ip(self, ip, source, host=None, role=None):
        try:
            ip = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            return False
        with self.lock:
            rec = self.ips.get(ip)
            if rec is None:
                rec = self.ips[ip] = {"sources": set(), "hosts": set(), "roles": set(), "intel": {}}
                self.counts[source]["ips"] += 1
            rec["sources"].add(source)
            if role:
                rec["roles"].add(role)
            if host:
                h = norm_host(host)
                if h:
                    rec["hosts"].add(h)
                    if h in self.hosts:
                        self.hosts[h]["ips"].add(ip)
        return True

    def ip_intel(self, ip):
        with self.lock:
            rec = self.ips.setdefault(ip, {"sources": set(), "hosts": set(), "roles": set(), "intel": {}})
            return rec["intel"]

    def add_url(self, url, source, **info):
        u = (url or "").strip().split("#", 1)[0]
        if not u or len(u) > 2048:
            return False
        try:
            sp = urllib.parse.urlsplit(u)
            host = (sp.hostname or "").lower()
        except ValueError:
            return False
        if sp.scheme not in ("http", "https") or not host or not self.in_scope(host):
            return False
        with self.lock:
            rec = self.urls.get(u)
            if rec is None:
                if len(self.urls) >= self.max_urls:
                    self.urls_dropped += 1
                    return False
                rec = self.urls[u] = {"sources": set(), "ts": info.get("ts"), "status": info.get("status"),
                                      "mime": info.get("mime")}
                self.counts[source]["urls"] += 1
            rec["sources"].add(source)
        # Only file the URL's host as a first-party "host" when scanning a domain and the host
        # matches that domain's scope. For a bare-IP target, in_scope() is trivially true for any
        # hostname (there is no domain suffix to compare against), so without this check every URL
        # host discovered via a shared IP (CDN, shared hosting, abuse feeds, ...) would wrongly be
        # filed as one of the target's own hosts instead of a merely-related domain.
        if self.t.kind == "domain":
            self.add_host(host, source)
        else:
            self.add_related(host, source, via="seen in a URL observed on this IP")
        return True

    def add_email(self, email, source):
        e = (email or "").strip().lower()
        if not EMAIL_RE.match(e):
            return False
        with self.lock:
            if e not in self.emails:
                self.emails[e] = set()
                self.counts[source]["emails"] += 1
            self.emails[e].add(source)
        return True

    def add_related(self, domain, source, via=""):
        d = norm_host(domain)
        if d.startswith("*."):
            d = d[2:]
        if not d or "." not in d or not HOST_RE.match(d) or is_ip(d):
            return False
        if self.t.kind == "domain" and self.in_scope(d):
            return False
        with self.lock:
            if d not in self.related:
                if len(self.related) >= 800:
                    return False
                self.related[d] = {"sources": set(), "via": via}
                self.counts[source]["related"] += 1
            self.related[d]["sources"].add(source)
        return True

    def add_netblock(self, cidr, source):
        try:
            net = str(ipaddress.ip_network(str(cidr).strip(), strict=False))
        except ValueError:
            return False
        with self.lock:
            if net not in self.netblocks and len(self.netblocks) >= 1500:
                return False
            self.netblocks.setdefault(net, set()).add(source)
        return True

    def add_tech(self, category, name, evidence, source):
        key = (category.lower(), name.lower())
        with self.lock:
            if key in self._tech_seen:
                return False
            self._tech_seen.add(key)
            self.tech.append({"category": category, "name": name, "evidence": short(evidence, 140), "source": source})
        return True

    def finding(self, sev, title, detail="", source=""):
        key = (sev, title, detail)
        with self.lock:
            if key in self._find_seen:
                return
            self._find_seen.add(key)
            self.findings.append({"severity": sev, "title": title, "detail": detail, "source": source})

    def status_entry(self, name):
        with self.lock:
            return self.status.setdefault(name, {"status": "pending", "message": "", "seconds": None, "warnings": []})

    def set_status(self, name, status, msg=None, seconds=None):
        with self.lock:
            st = self.status_entry(name)
            st["status"] = status
            if msg is not None:
                st["message"] = msg
            if seconds is not None:
                st["seconds"] = round(seconds, 1)


class Ctx:
    def __init__(self, target, res, http, doh, keys, args, log):
        self.target, self.res, self.http, self.doh = target, res, http, doh
        self.keys, self.args, self.log = keys, args, log
        self.ip_targets = []

    def key(self, *names):
        for n in names:
            v = self.keys.get(n)
            if v:
                return v
        return None

    def warn(self, msg):
        name = getattr(_TLS, "module", None)
        if name:
            with self.res.lock:
                w = self.res.status_entry(name)["warnings"]
                if len(w) < 10:
                    w.append(short(msg, 160))

    def file_hostname(self, host, source):
        """File a hostname discovered via a third-party data source (Shodan, InternetDB, ...) as a
        first-party host only when scanning a domain and the name matches that domain's scope;
        otherwise (a bare-IP target, or a name outside the scanned domain) file it as a merely
        related/associated domain. A bare-IP target has no domain suffix to compare against, so
        in_scope() alone can't make this call — without the explicit kind check, every hostname
        sharing the target IP (shared hosting, a CDN, ...) would be mislabeled as the target's own."""
        if self.target.kind == "domain" and self.res.in_scope(norm_host(host)):
            return self.res.add_host(host, source)
        return self.res.add_related(host, source)

    def each_ip(self, fn, max_fail=3):
        """Run fn(ip) for every IP to enrich; tolerate isolated failures, stop on repeated ones."""
        fails = 0
        for ip in list(self.ip_targets):
            try:
                fn(ip)
                fails = 0
            except SourceError as e:
                fails += 1
                self.warn("%s: %s" % (ip, e))
                if fails >= max_fail:
                    raise SourceError("stopped after %d consecutive failures: %s" % (fails, e))


MODULES = {}


def module(name, modes=("domain",), keys=(), phase=1, desc=""):
    def deco(fn):
        MODULES[name] = {"name": name, "fn": fn, "modes": set(modes), "keys": tuple(keys), "phase": phase, "desc": desc}
        return fn
    return deco


# ============================================================================
# RDAP (WHOIS replacement, RFC 9083) with IANA bootstrap fallback
# ============================================================================
_RDAP_BOOT_CACHE = {}
_RDAP_BOOT_LOCK = threading.Lock()


def _rdap_bootstrap(http, kind):
    with _RDAP_BOOT_LOCK:
        if kind in _RDAP_BOOT_CACHE:
            return _RDAP_BOOT_CACHE[kind]
    url = "https://data.iana.org/rdap/%s.json" % ("dns" if kind == "domain" else kind)
    j = http.get_json(url, timeout=15, retries=1)
    with _RDAP_BOOT_LOCK:
        _RDAP_BOOT_CACHE[kind] = j.get("services", [])
        return _RDAP_BOOT_CACHE[kind]


def _rdap_server_for(http, kind, identifier):
    if kind == "domain":
        tld = identifier.rsplit(".", 1)[-1]
        for services in _rdap_bootstrap(http, "domain"):
            if len(services) >= 2 and tld in [s.lower() for s in services[0]]:
                return services[1][0].rstrip("/")
    else:
        ipver = "ipv4" if "." in identifier else "ipv6"
        net = ipaddress.ip_address(identifier)
        for services in _rdap_bootstrap(http, ipver):
            if len(services) < 2:
                continue
            for cidr in services[0]:
                try:
                    if net in ipaddress.ip_network(cidr, strict=False):
                        return services[1][0].rstrip("/")
                except ValueError:
                    continue
    return None


def rdap_lookup(ctx, kind, identifier):
    """kind: 'domain' or 'ip'. Returns the parsed RDAP JSON object or raises SourceError."""
    path = "domain" if kind == "domain" else "ip"
    errors = []
    try:
        return ctx.http.get_json("https://rdap.org/%s/%s" % (path, identifier), timeout=20, retries=1)
    except SourceError as e:
        errors.append("rdap.org: %s" % e)
    try:
        server = _rdap_server_for(ctx.http, kind, identifier)
        if server:
            return ctx.http.get_json("%s/%s/%s" % (server, path, identifier), timeout=20, retries=1)
        errors.append("no RDAP server found for %s via IANA bootstrap" % identifier)
    except SourceError as e:
        errors.append("IANA bootstrap: %s" % e)
    raise SourceError("; ".join(errors))


def rdap_vcard_text(vcard, label):
    if not vcard or len(vcard) < 2:
        return None
    for entry in vcard[1]:
        if len(entry) >= 4 and entry[0] == label:
            v = entry[3]
            if isinstance(v, str):
                return v
            if isinstance(v, list):
                return " ".join(x for x in v if x) or None
    return None


def parse_rdap_domain(j):
    out = {"handle": j.get("handle"), "statuses": j.get("status") or [], "nameservers": [], "events": {},
          "entities": [], "dnssec": None}
    for ns in j.get("nameservers") or []:
        n = (ns.get("ldhName") or "").rstrip(".").lower()
        if n:
            out["nameservers"].append(n)
    for ev in j.get("events") or []:
        act, date = ev.get("eventAction"), ev.get("eventDate")
        if act and date:
            out["events"][act] = date
    sd = j.get("secureDNS")
    if sd is not None:
        out["dnssec"] = bool(sd.get("delegationSigned"))

    def _collect(ent):
        roles = ent.get("roles") or []
        name = rdap_vcard_text(ent.get("vcardArray"), "fn")
        org = rdap_vcard_text(ent.get("vcardArray"), "org")
        email = rdap_vcard_text(ent.get("vcardArray"), "email")
        if roles or name or org:
            out["entities"].append({"roles": roles, "name": name, "org": org, "email": email,
                                    "handle": ent.get("handle")})
        for sub in ent.get("entities") or []:
            _collect(sub)
    for ent in j.get("entities") or []:
        _collect(ent)
    links = [l.get("href") for l in (j.get("links") or []) if l.get("rel") == "related" and l.get("href")]
    if links:
        out["links"] = links
    return out


def parse_rdap_ip(j):
    out = {"handle": j.get("handle"), "name": j.get("name"), "type": j.get("type"), "country": j.get("country"),
          "parent_handle": j.get("parentHandle"), "start": j.get("startAddress"), "end": j.get("endAddress"),
          "cidrs": [], "org": None, "abuse_email": None, "events": {}}
    for c in j.get("cidr0_cidrs") or []:
        v4, v6, pfx = c.get("v4prefix"), c.get("v6prefix"), c.get("length")
        if v4:
            out["cidrs"].append("%s/%s" % (v4, pfx))
        elif v6:
            out["cidrs"].append("%s/%s" % (v6, pfx))
    for ev in j.get("events") or []:
        if ev.get("eventAction") and ev.get("eventDate"):
            out["events"][ev["eventAction"]] = ev["eventDate"]

    def _scan(ent):
        roles = ent.get("roles") or []
        name = rdap_vcard_text(ent.get("vcardArray"), "fn")
        if name and not out["org"]:
            out["org"] = name
        if "abuse" in roles and not out["abuse_email"]:
            em = rdap_vcard_text(ent.get("vcardArray"), "email")
            if em:
                out["abuse_email"] = em
        for sub in ent.get("entities") or []:
            _scan(sub)
    for ent in j.get("entities") or []:
        _scan(ent)
    return out


# ============================================================================
# Phase-1 modules: DNS, RDAP, certificate transparency, web archives
# ============================================================================
SUBDOMAIN_WORDLIST = sorted(set("""
www mail smtp pop pop3 imap webmail email autodiscover autoconfig ns ns1 ns2 ns3 ns4 dns dns1 dns2
mx mx1 mx2 ftp sftp ftps ssh vpn remote rdp admin administrator portal login signin sso auth
api api1 api2 gateway dev development test testing stage staging uat qa demo sandbox beta preview
app apps mobile m web2 static assets cdn media img images js css
blog shop store support help helpdesk docs doc documentation status statuspage
db database mysql postgres redis mongo es elastic search
git gitlab github ci jenkins build registry docker k8s kube grafana kibana prometheus sonar nexus
internal intranet corp office extranet partner partners
secure security payments payment pay billing account accounts my
cpanel whm webdisk ntp time
old new beta2 v1 v2 v3 origin direct edge gw proxy cache
chat voice video stream streaming cdn1 cdn2 download downloads files file upload uploads
crm erp hr jira confluence wiki kb news careers jobs press
""".split()))


def _spf_lookup_chain(ctx, domain, depth=0, seen=None, out=None):
    seen = seen if seen is not None else set()
    out = out if out is not None else {"mechanisms": [], "includes": [], "all": None, "lookups": 0}
    if depth > 6 or domain in seen or out["lookups"] >= 10:
        return out
    seen.add(domain)
    try:
        ans = ctx.doh.query(domain, "TXT")
    except SourceError:
        return out
    spf = next((a["data"] for a in ans["answers"] if a["data"].lower().startswith("v=spf1")), None)
    if not spf:
        return out
    out["lookups"] += 1
    for tok in spf.split():
        if tok == "v=spf1":
            continue
        bare = tok.lstrip("+-~?")
        if bare.startswith("all"):
            out["all"] = tok
        elif tok.startswith("include:"):
            inc = tok.split(":", 1)[1]
            out["includes"].append(inc)
            out["mechanisms"].append(tok)
            _spf_lookup_chain(ctx, inc, depth + 1, seen, out)
        elif tok.startswith("redirect="):
            out["mechanisms"].append(tok)
            _spf_lookup_chain(ctx, tok.split("=", 1)[1], depth + 1, seen, out)
        else:
            out["mechanisms"].append(tok)
    return out


@module("dns", modes=("domain",), phase=1,
        desc="Apex DNS records, mail-security posture (SPF/DKIM/DMARC), wildcard check & common-name wordlist — all via public resolvers")
def mod_dns(ctx):
    res, doh, domain = ctx.res, ctx.doh, ctx.target.scope
    d = res.dns.setdefault(domain, {})
    found_any = False
    for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA"):
        try:
            ans = doh.query(domain, rtype)
        except SourceError as e:
            ctx.warn("%s %s: %s" % (domain, rtype, e))
            continue
        recs = [a["data"] for a in ans["answers"] if a["type"] == rtype]
        if recs:
            d[rtype] = recs
            found_any = True
        for a in ans["answers"]:
            if a["type"] == "A":
                res.add_ip(a["data"], "dns", host=domain, role="A")
            elif a["type"] == "AAAA":
                res.add_ip(a["data"], "dns", host=domain, role="AAAA")
            elif a["type"] == "NS":
                prov = match_table(a["data"], NS_PROVIDERS)
                if prov:
                    res.add_tech("DNS hosting", prov, a["data"], "dns")
                res.add_related(a["data"], "dns", via="nameserver")
            elif a["type"] == "MX":
                host = a["data"].split(None, 1)[-1]
                prov = match_table(host, MX_PROVIDERS)
                if prov:
                    res.add_tech("Email hosting", prov, host, "dns")
                res.add_related(host, "dns", via="mail exchanger")
    if not found_any:
        raise SourceError("no DNS records returned for %s via public resolvers (NXDOMAIN or resolver failure)" % domain)
    res.add_host(domain, "dns")

    probe = "_wc%d.%s" % (random.randint(10000, 99999), domain)
    try:
        wc = doh.query(probe, "A")
        if wc["answers"]:
            d["wildcard"] = sorted({a["data"] for a in wc["answers"] if a["type"] == "A"})
            res.finding("info", "Wildcard DNS is configured on %s" % domain,
                       "Any undefined subdomain resolves (e.g. to %s), so DNS presence alone is not proof a "
                       "subdomain is actually in use." % ", ".join(d["wildcard"]), "dns")
    except SourceError:
        pass

    spf_chain = _spf_lookup_chain(ctx, domain)
    rec = None
    if spf_chain["lookups"]:
        d["spf"] = spf_chain
        for inc in spf_chain["includes"]:
            v = match_table(inc, SPF_VENDORS)
            if v:
                res.add_tech("Email sender / marketing", v, inc, "dns")
        if spf_chain["all"] in ("+all", "all"):
            res.finding("high", "SPF allows any server to send mail (+all)",
                       "The SPF record for %s ends in '+all', permitting any host on the internet to send mail "
                       "as this domain. This should almost always be '-all' or '~all'." % domain, "dns")
        elif spf_chain["all"] is None:
            res.finding("low", "SPF record has no explicit 'all' mechanism", "", "dns")
        elif spf_chain["all"] == "~all":
            res.finding("info", "SPF uses a soft fail (~all)",
                       "Spoofed mail is flagged but not necessarily rejected; '-all' is stricter.", "dns")
    else:
        res.finding("medium", "No SPF record found",
                   "Without SPF, receiving mail servers have no record of which hosts are authorised to send "
                   "mail for %s, making spoofing easier." % domain, "dns")

    try:
        dm = doh.query("_dmarc." + domain, "TXT")
        rec = next((a["data"] for a in dm["answers"] if a["data"].lower().startswith("v=dmarc1")), None)
    except SourceError:
        pass
    if rec:
        d["dmarc"] = rec
        pm = re.search(r"p=(\w+)", rec, re.I)
        policy = pm.group(1).lower() if pm else None
        d["dmarc_policy"] = policy
        if policy == "none":
            res.finding("medium", "DMARC policy is 'p=none'",
                       "DMARC is published but set to monitor-only; spoofed mail is not rejected or quarantined.", "dns")
        for addr in re.findall(r"ru[af]=mailto:([^,;\s]+)", rec, re.I):
            res.add_email(addr, "dns")
            v = match_table(addr.split("@")[-1], DMARC_VENDORS)
            if v:
                res.add_tech("DMARC monitoring", v, addr, "dns")
    else:
        res.finding("medium", "No DMARC record found (_dmarc TXT)",
                   "Without DMARC, even a strict SPF/DKIM setup gives receivers no instruction on what to do "
                   "with mail that fails authentication.", "dns")

    dkim_hits = []

    def _dkim(sel):
        name = "%s._domainkey.%s" % (sel, domain)
        try:
            ans = doh.query(name, "TXT")
            if ans["answers"]:
                return sel, ans["answers"][0]["data"]
            ans = doh.query(name, "CNAME")
            if ans["answers"]:
                return sel, "CNAME " + ans["answers"][0]["data"]
        except SourceError:
            pass
        return None
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(_dkim, DKIM_SELECTORS):
            if r:
                dkim_hits.append(r)
    if dkim_hits:
        d["dkim_selectors"] = dict(dkim_hits)
        for sel, val in dkim_hits:
            label = SELECTOR_GUESS.get(sel) or match_table(val, DKIM_VENDORS)
            if label:
                res.add_tech("Email sender (DKIM)", label, "%s: %s" % (sel, short(val, 60)), "dns")

    for txt in d.get("TXT", []):
        for pat, label in TXT_VERIFY:
            if pat.match(txt):
                res.add_tech("Linked service (TXT verification record)", label, txt, "dns")
                break

    def _try(word):
        name = "%s.%s" % (word, domain)
        try:
            a4 = doh.query(name, "A")
        except SourceError:
            return
        ans = a4["answers"]
        if a4["rcode"] != 0 or not ans:
            try:
                cn = doh.query(name, "CNAME")
            except SourceError:
                return
            if not cn["answers"]:
                return
            ans = cn["answers"]
        if d.get("wildcard") and {x["data"] for x in ans if x["type"] == "A"} and \
                {x["data"] for x in ans if x["type"] == "A"} <= set(d["wildcard"]):
            return
        res.add_host(name, "dns-wordlist")
        for a in ans:
            if a["type"] == "A":
                res.add_ip(a["data"], "dns-wordlist", host=name, role="A")
            elif a["type"] == "CNAME":
                res.hosts[name]["cnames"].append(a["data"])
                svc, _ = match_service(a["data"])
                if svc:
                    res.add_tech("Hosting / platform", svc, a["data"], "dns-wordlist")
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(_try, SUBDOMAIN_WORDLIST))

    return "apex records ok; %d wordlist probes; wildcard=%s spf=%s dmarc=%s dkim_selectors=%d" % (
        len(SUBDOMAIN_WORDLIST), bool(d.get("wildcard")), bool(spf_chain["lookups"]), bool(rec), len(dkim_hits))


@module("rdap", modes=("domain",), phase=1,
        desc="Domain registration data via RDAP (registrar, dates, nameservers, DNSSEC, public contacts)")
def mod_rdap_domain(ctx):
    domain = ctx.target.scope
    j = rdap_lookup(ctx, "domain", domain)
    parsed = parse_rdap_domain(j)
    ctx.res.whois[domain] = parsed
    for ns in parsed["nameservers"]:
        ctx.res.add_related(ns, "rdap", via="nameserver")
    for ent in parsed["entities"]:
        if ent.get("email"):
            ctx.res.add_email(ent["email"], "rdap")
    if parsed["dnssec"] is False:
        ctx.res.finding("low", "DNSSEC is not enabled for %s" % domain, "", "rdap")
    exp = parsed["events"].get("expiration")
    if exp:
        edt = parse_dt(exp)
        if edt and edt < utcnow() + dt.timedelta(days=30):
            days = (edt - utcnow()).days
            sev = "high" if days < 0 else "medium"
            ctx.res.finding(sev, "Domain registration %s" % ("has already lapsed" if days < 0 else "expires within 30 days"),
                           "Expiry date on record: %s (%s %d day(s))." % (exp, "overdue by" if days < 0 else "in", abs(days)),
                           "rdap")
    registrar = next((e.get("name") or e.get("org") for e in parsed["entities"] if "registrar" in (e.get("roles") or [])), "?")
    return "registrar=%s, nameservers=%d, dnssec=%s" % (registrar, len(parsed["nameservers"]), parsed["dnssec"])


@module("crtsh", modes=("domain",), phase=1,
        desc="Certificate Transparency logs via crt.sh — historical subdomains, certificate issuers and validity windows")
def mod_crtsh(ctx):
    domain = ctx.target.scope
    rows = ctx.http.get_json("https://crt.sh/?q=%s&output=json" % quote(domain), timeout=45, retries=1)
    if not isinstance(rows, list):
        raise SourceError("unexpected response shape from crt.sh (it may be temporarily overloaded)")
    if not rows:
        return "no certificates found"
    issuers, earliest, latest, wildcards = Counter(), None, None, 0
    names = set()
    for row in rows:
        issuers[row.get("issuer_name", "unknown")] += 1
        nb, na = parse_dt(row.get("not_before")), parse_dt(row.get("not_after"))
        if nb and (earliest is None or nb < earliest):
            earliest = nb
        if na and (latest is None or na > latest):
            latest = na
        for n in (row.get("name_value") or "").split("\n") + [row.get("common_name") or ""]:
            n = n.strip().lower()
            if n.startswith("*."):
                wildcards += 1
                n = n[2:]
            if n:
                names.add(n)
    for n in names:
        ctx.res.add_host(n, "crtsh")
    ctx.res.certs["crtsh"] = {"certificates": len(rows), "unique_names": len(names), "top_issuers": issuers.most_common(8),
                              "wildcards_seen": wildcards, "earliest_not_before": earliest.isoformat() if earliest else None,
                              "latest_not_after": latest.isoformat() if latest else None}
    for ca, _n in issuers.most_common(3):
        label = next((v for k, v in [("let's encrypt", "Let's Encrypt"), ("digicert", "DigiCert"), ("sectigo", "Sectigo"),
                                     ("google trust", "Google Trust Services"), ("amazon", "Amazon (ACM)"),
                                     ("cloudflare", "Cloudflare"), ("zerossl", "ZeroSSL"), ("godaddy", "GoDaddy"),
                                     ("globalsign", "GlobalSign")] if k in ca.lower()), None)
        if label:
            ctx.res.add_tech("Certificate authority", label, ca, "crtsh")
    if earliest:
        ctx.res.extras["first_cert_seen"] = earliest.strftime("%Y-%m-%d")
    return "%d certificates, %d unique hostnames, %d distinct issuers" % (len(rows), len(names), len(issuers))


@module("certspotter", modes=("domain",), phase=1, keys=(),
        desc="Certificate Transparency via SSLMate CertSpotter (anonymous tier unless CERTSPOTTER_API_KEY is set)")
def mod_certspotter(ctx):
    domain = ctx.target.scope
    headers = {}
    key = ctx.key("CERTSPOTTER_API_KEY")
    if key:
        headers["Authorization"] = "Bearer " + key
    url = "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names" % quote(domain)
    rows = ctx.http.get_json(url, headers=headers, timeout=30, retries=1)
    if not isinstance(rows, list):
        raise SourceError("unexpected response shape from CertSpotter")
    names = set()
    for row in rows:
        for n in row.get("dns_names") or []:
            n = n.strip().lower()
            if n.startswith("*."):
                n = n[2:]
            if n:
                names.add(n)
    for n in names:
        ctx.res.add_host(n, "certspotter")
    ctx.res.certs["certspotter"] = {"issuances": len(rows), "unique_names": len(names)}
    return "%d issuances, %d unique hostnames%s" % (len(rows), len(names), "" if key else " (anonymous tier)")


@module("wayback", modes=("domain",), phase=1,
        desc="Internet Archive Wayback Machine CDX index — historical URLs, status codes and MIME types")
def mod_wayback(ctx):
    domain = ctx.target.scope
    url = ("https://web.archive.org/cdx/search/cdx?url=%s%%2F*&matchType=domain&output=json"
          "&fl=original,timestamp,mimetype,statuscode&collapse=urlkey&limit=20000" % quote(domain))
    rows = ctx.http.get_json(url, timeout=60, retries=1)
    if not isinstance(rows, list) or not rows:
        return "no archived URLs found"
    if rows and rows[0][:1] == ["original"]:
        rows = rows[1:]
    cats, examples = Counter(), defaultdict(list)
    first_ts = last_ts = None
    for row in rows:
        if len(row) < 4:
            continue
        original, ts, mime, status = row[0], row[1], row[2], row[3]
        ctx.res.add_url(original, "wayback", ts=ts_date(ts), status=status, mime=mime)
        if first_ts is None or ts < first_ts:
            first_ts = ts
        if last_ts is None or ts > last_ts:
            last_ts = ts
        for cat, pat in URL_CATEGORIES:
            if pat.search(original):
                cats[cat] += 1
                if len(examples[cat]) < 5:
                    examples[cat].append(original)
                break
    ctx.res.extras["wayback"] = {"unique_urls": len(rows), "first_seen": ts_date(first_ts), "last_seen": ts_date(last_ts)}
    for cat, n in cats.most_common():
        sev = "medium" if cat in ("Secrets & config files", "Backups & dumps") else \
              "low" if cat in ("Logs & debug endpoints", "Admin & login panels") else "info"
        ctx.res.finding(sev, "%d archived URL(s) matching '%s'" % (n, cat),
                       "Examples: " + "; ".join(examples[cat]) + (" ..." if n > len(examples[cat]) else "") +
                       ". These are historical Wayback Machine captures — not confirmation the path is live today.",
                       "wayback")
    return "%d unique archived URLs spanning %s to %s" % (len(rows), ts_date(first_ts), ts_date(last_ts))


WELL_KNOWN_PATHS = ["robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
                    "humans.txt", "crossdomain.xml", ".well-known/openid-configuration"]


@module("wayback-files", modes=("domain",), phase=1,
        desc="Archived robots.txt / sitemap.xml / security.txt content, read from the Wayback Machine (never fetched from the target itself)")
def mod_wayback_files(ctx):
    domain, hits, checked, last_err = ctx.target.scope, [], 0, None
    for path in WELL_KNOWN_PATHS:
        target_url = "https://%s/%s" % (domain, path)
        try:
            avail = ctx.http.get_json("https://archive.org/wayback/available?url=%s" % quote(target_url), timeout=15, retries=1)
        except SourceError as e:
            last_err = e
            continue
        checked += 1
        snap = (avail.get("archived_snapshots") or {}).get("closest")
        if not snap or not snap.get("available"):
            continue
        ts = snap.get("timestamp", "")
        raw_url = "https://web.archive.org/web/%sid_/%s" % (ts, target_url)
        try:
            body = ctx.http.get_text(raw_url, timeout=20, retries=1, max_bytes=300000)
        except SourceError:
            continue
        hits.append(path)
        if path == "robots.txt":
            disallows = sorted(set(re.findall(r"(?im)^\s*Disallow:\s*(\S+)", body)))[:60]
            if disallows:
                ctx.res.extras["robots_disallow"] = disallows
                for p in disallows:
                    ctx.res.add_url(urllib.parse.urljoin("https://%s/" % domain, p), "wayback-files")
                ctx.res.finding("info", "Archived robots.txt lists %d disallowed path(s)" % len(disallows),
                               "Captured %s. These paths were intentionally hidden from crawlers, which "
                               "sometimes makes them worth a manual look." % ts_date(ts), "wayback-files")
        elif "security.txt" in path:
            for em in re.findall(r"(?im)^Contact:\s*mailto:(\S+)", body):
                ctx.res.add_email(em, "wayback-files")
            ctx.res.finding("info", "Archived security.txt found", "Captured %s." % ts_date(ts), "wayback-files")
        elif path == "sitemap.xml":
            for loc in re.findall(r"<loc>([^<]+)</loc>", body)[:500]:
                ctx.res.add_url(htmllib.unescape(loc.strip()), "wayback-files")
    if checked == 0:
        raise SourceError("could not reach the Wayback Machine for any of %d well-known paths: %s" %
                          (len(WELL_KNOWN_PATHS), last_err))
    if not hits:
        return "checked %d well-known path(s), none archived" % checked
    return "found archived copies of: %s" % ", ".join(hits)


@module("commoncrawl", modes=("domain",), phase=1,
        desc="Common Crawl index — additional historical URL discovery from the most recent crawl snapshots")
def mod_commoncrawl(ctx):
    domain = ctx.target.scope
    colls = ctx.http.get_json("https://index.commoncrawl.org/collinfo.json", timeout=20, retries=1)
    if not isinstance(colls, list) or not colls:
        raise SourceError("could not list Common Crawl collections")
    found = 0
    used = 0
    for coll in colls[:3]:
        api = coll.get("cdx-api")
        if not api:
            continue
        used += 1
        url = "%s?url=%s%%2F*&matchType=domain&output=json&limit=3000&fl=url,timestamp,mime,status" % (api, quote(domain))
        try:
            _, _, body = ctx.http.request(url, timeout=40, retries=1, ok_statuses=(200, 404))
        except SourceError as e:
            ctx.warn("%s: %s" % (coll.get("id"), e))
            continue
        for line in body.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if ctx.res.add_url(row.get("url", ""), "commoncrawl", ts=ts_date(row.get("timestamp")),
                               status=row.get("status"), mime=row.get("mime")):
                found += 1
    return "%d additional URLs across %d recent crawl snapshot(s)" % (found, used)


# ============================================================================
# Phase-1 modules: free third-party recon APIs (subdomains, reverse-IP, threat intel)
# ============================================================================
def _hackertarget(ctx, endpoint, q):
    body = ctx.http.get_text("https://api.hackertarget.com/%s/?q=%s" % (endpoint, quote(q)), timeout=20, retries=1)
    if "error" in body.lower() or "API count exceeded" in body:
        raise SourceError("hackertarget.com: %s" % short(body, 100))
    return body


@module("hackertarget", modes=("domain", "ip"), phase=1,
        desc="HackerTarget free API — subdomains (domain mode) or reverse-IP neighbours/ASN/geoIP (IP mode)")
def mod_hackertarget(ctx):
    notes = []
    if ctx.target.kind == "domain":
        domain = ctx.target.scope
        body = _hackertarget(ctx, "hostsearch", domain)
        n = 0
        for line in body.splitlines():
            parts = line.split(",")
            if len(parts) >= 2 and HOST_RE.match(parts[0].strip().lower()):
                ctx.res.add_host(parts[0].strip(), "hackertarget")
                ctx.res.add_ip(parts[1].strip(), "hackertarget", host=parts[0].strip())
                n += 1
        notes.append("%d host(s) from hostsearch" % n)
    else:
        ip = ctx.target.ip
        try:
            geo = _hackertarget(ctx, "geoip", ip)
            ctx.res.ip_intel(ip)["hackertarget_geoip"] = geo.strip()
            notes.append("geoip ok")
        except SourceError as e:
            ctx.warn(str(e))
        try:
            asn = _hackertarget(ctx, "aslookup", ip)
            ctx.res.ip_intel(ip)["hackertarget_asn"] = asn.strip()
            notes.append("asn ok")
        except SourceError as e:
            ctx.warn(str(e))
        try:
            rev = _hackertarget(ctx, "reverseiplookup", ip)
            hosts = [h.strip() for h in rev.splitlines() if HOST_RE.match(h.strip().lower())]
            for h in hosts[:500]:
                ctx.res.add_related(h, "hackertarget", via="shares this IP address")
            notes.append("%d neighbour host(s) on this IP" % len(hosts))
        except SourceError as e:
            ctx.warn(str(e))
    if not notes:
        raise SourceError("all hackertarget.com endpoints failed (its free daily quota is shared per client IP)")
    return "; ".join(notes)


@module("otx", modes=("domain", "ip"), phase=1,
        desc="AlienVault OTX — passive DNS, related URLs and threat-intel pulse context (OTX_API_KEY optional, raises the rate limit)")
def mod_otx(ctx):
    headers = {}
    key = ctx.key("OTX_API_KEY")
    if key:
        headers["X-OTX-API-KEY"] = key
    kind, ident = ("domain", ctx.target.scope) if ctx.target.kind == "domain" else ("IPv4", ctx.target.ip)
    base = "https://otx.alienvault.com/api/v1/indicators/%s/%s" % (kind, quote(ident))
    notes = []
    try:
        pdns = ctx.http.get_json(base + "/passive_dns", headers=headers, timeout=25, retries=1)
        entries = pdns.get("passive_dns") or []
        for e in entries[:1500]:
            host, addr = e.get("hostname"), e.get("address")
            if host:
                (ctx.res.add_host if ctx.target.kind == "domain" else ctx.res.add_related)(host, "otx")
            if addr and is_ip(addr):
                ctx.res.add_ip(addr, "otx", host=host)
        notes.append("%d passive DNS record(s)" % len(entries))
    except SourceError as e:
        ctx.warn("passive_dns: %s" % e)
    try:
        gen = ctx.http.get_json(base + "/general", headers=headers, timeout=20, retries=1)
        pulses = (gen.get("pulse_info") or {}).get("count", 0)
        if pulses:
            ctx.res.finding("medium" if pulses > 2 else "low", "Appears in %d AlienVault OTX threat-intel pulse(s)" % pulses,
                           "Community-submitted threat pulses reference this indicator; investigate before assuming malice.", "otx")
        notes.append("%d pulse(s)" % pulses)
    except SourceError as e:
        ctx.warn("general: %s" % e)
    if ctx.target.kind == "domain":
        try:
            urls = ctx.http.get_json(base + "/url_list?limit=100", headers=headers, timeout=25, retries=1)
            ulist = urls.get("url_list") or []
            for u in ulist:
                ctx.res.add_url(u.get("url", ""), "otx")
            notes.append("%d URL(s)" % len(ulist))
        except SourceError as e:
            ctx.warn("url_list: %s" % e)
    if not notes:
        raise SourceError("all OTX endpoints failed" + ("" if key else " (try setting OTX_API_KEY)"))
    return "; ".join(notes)


@module("urlscan", modes=("domain", "ip"), phase=1,
        desc="urlscan.io search — past scans: resolved IP/ASN, server headers, page titles, detected technologies")
def mod_urlscan(ctx):
    headers = {}
    key = ctx.key("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key
    q = "page.domain:%s OR domain:%s" % (ctx.target.scope, ctx.target.scope) if ctx.target.kind == "domain" \
        else "page.ip:%s OR ip:%s" % (ctx.target.ip, ctx.target.ip)
    j = ctx.http.get_json("https://urlscan.io/api/v1/search/?q=%s&size=100" % quote(q), headers=headers, timeout=25, retries=1)
    results = j.get("results") or []
    servers, titles, techs = Counter(), [], Counter()
    for r in results:
        page = r.get("page") or {}
        if page.get("domain") and ctx.target.kind == "domain":
            ctx.res.add_host(page["domain"], "urlscan")
        if page.get("ip"):
            ctx.res.add_ip(page["ip"], "urlscan", host=page.get("domain"))
        if page.get("server"):
            servers[page["server"]] += 1
        if page.get("title") and len(titles) < 10 and page["title"] not in titles:
            titles.append(page["title"])
        if page.get("url"):
            ctx.res.add_url(page["url"], "urlscan")
        for t in r.get("tags") or []:
            techs[t] += 1
    for srv, _n in servers.most_common(5):
        ctx.res.add_tech("Web server", srv, "seen in urlscan.io captures", "urlscan")
    for t, _n in techs.most_common(15):
        ctx.res.add_tech("Detected by urlscan.io", t, "", "urlscan")
    if titles:
        ctx.res.extras["page_titles"] = titles
    return "%d historical scan(s), %d distinct server header(s)" % (len(results), len(servers))


@module("anubis", modes=("domain",), phase=1, desc="jldc.me Anubis subdomain database")
def mod_anubis(ctx):
    domain = ctx.target.scope
    data = ctx.http.get_json("https://jldc.me/anubis/subdomains/%s" % quote(domain), timeout=20, retries=1)
    if not isinstance(data, list):
        raise SourceError("unexpected response shape")
    for n in data:
        ctx.res.add_host(n, "anubis")
    return "%d hostname(s)" % len(data)


@module("columbus", modes=("domain",), phase=1, desc="Columbus Project subdomain database")
def mod_columbus(ctx):
    domain = ctx.target.scope
    data = ctx.http.get_json("https://columbus.elmasy.com/api/lookup/%s" % quote(domain), timeout=20, retries=1)
    if not isinstance(data, list):
        raise SourceError("unexpected response shape")
    n = 0
    for sub in data:
        if not sub:
            continue
        name = sub if str(sub).endswith(domain) else "%s.%s" % (sub, domain)
        if ctx.res.add_host(name, "columbus"):
            n += 1
    return "%d hostname(s)" % n


@module("urlhaus", modes=("domain", "ip"), phase=1, desc="abuse.ch URLhaus — known malware-distribution URLs hosted on this domain/IP")
def mod_urlhaus(ctx):
    host = ctx.target.scope if ctx.target.kind == "domain" else ctx.target.ip
    data = urllib.parse.urlencode({"host": host}).encode()
    _, _, body = ctx.http.request("https://urlhaus-api.abuse.ch/v1/host/", method="POST", data=data,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=20, retries=1)
    j = parse_json(body)
    status = j.get("query_status")
    if status == "no_results":
        return "no known malware URLs"
    if status != "ok":
        raise SourceError("query status: %s" % status)
    urls = j.get("urls") or []
    for u in urls[:200]:
        ctx.res.add_url(u.get("url", ""), "urlhaus")
    if urls:
        ctx.res.finding("high", "%d URL(s) on this host flagged in abuse.ch URLhaus (malware distribution)" % len(urls),
                       "Most recent: %s — %s" % (urls[0].get("date_added", "?"), urls[0].get("url", "")), "urlhaus")
    return "%d malicious URL(s) on record" % len(urls)


@module("threatfox", modes=("domain", "ip"), phase=1, desc="abuse.ch ThreatFox — IOC search for this domain/IP (botnet C2, malware infrastructure)")
def mod_threatfox(ctx):
    search = ctx.target.scope if ctx.target.kind == "domain" else ctx.target.ip
    data = json.dumps({"query": "search_ioc", "search_term": search}).encode()
    _, _, body = ctx.http.request("https://threatfox-api.abuse.ch/api/v1/", method="POST", data=data,
                                  headers={"Content-Type": "application/json"}, timeout=20, retries=1)
    j = parse_json(body)
    status = j.get("query_status")
    if status in ("no_result", "no_results"):
        return "no IOC matches"
    if status != "ok":
        raise SourceError("query status: %s" % status)
    rows = j.get("data") or []
    types = Counter(r.get("malware_printable", r.get("threat_type", "unknown")) for r in rows)
    if rows:
        ctx.res.finding("high", "%d indicator(s) of compromise matched in ThreatFox" % len(rows),
                       "Associated malware/threat types: %s" % ", ".join("%s (%d)" % kv for kv in types.most_common(5)),
                       "threatfox")
    return "%d IOC match(es): %s" % (len(rows), ", ".join("%s x%d" % kv for kv in types.most_common(3)) or "-")


@module("m365", modes=("domain",), phase=1,
        desc="Microsoft realm/federation lookup — reveals Microsoft 365 / Entra ID tenant use and sibling verified domains on the same tenant")
def mod_m365(ctx):
    domain = ctx.target.scope
    probe_login = "nonexistent-user-probe@" + domain
    body = ctx.http.get_text("https://login.microsoftonline.com/getuserrealm.srf?login=%s&xml=1" % quote(probe_login),
                             timeout=15, retries=1)
    ns = re.search(r"<NameSpaceType>([^<]+)</NameSpaceType>", body)
    if not ns or ns.group(1) in ("", "Unknown"):
        raise SourceError("domain is not associated with a Microsoft 365 / Entra ID tenant")
    namespace = ns.group(1)
    ctx.res.add_tech("Identity provider", "Microsoft 365 / Entra ID (%s)" % namespace, domain, "m365")
    brand = re.search(r"<FederationBrandName>([^<]*)</FederationBrandName>", body)
    auth_url = re.search(r"<AuthURL>([^<]*)</AuthURL>", body)
    ctx.res.extras["m365_tenant"] = {"namespace_type": namespace, "federation_brand": brand.group(1) if brand else None,
                                     "auth_url": auth_url.group(1) if auth_url else None}
    siblings = 0
    try:
        soap = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
               '<soap:Body><GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">'
               '<Request><Domain>%s</Domain></Request></GetFederationInformationRequestMessage></soap:Body></soap:Envelope>' % domain)
        _, _, resp = ctx.http.request(
            "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc", method="POST", data=soap.encode(),
            headers={"Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"'},
            timeout=15, retries=1)
        for sib in re.findall(r"<Domain>([^<]+)</Domain>", resp.decode("utf-8", "replace")):
            if ctx.res.add_related(sib, "m365", via="shares this Microsoft 365 / Entra ID tenant"):
                siblings += 1
    except SourceError as e:
        ctx.warn("GetFederationInformation: %s" % e)
    return "namespace=%s, brand=%s, +%d sibling domain(s) on the same tenant" % (
        namespace, (brand.group(1) if brand else "?"), siblings)


@module("github", modes=("domain",), phase=1, keys=("GITHUB_TOKEN",),
        desc="GitHub code search — public files/repos mentioning this domain (possible leaked configs/credentials)")
def mod_github(ctx):
    token = ctx.key("GITHUB_TOKEN")
    if not token:
        raise SourceError("requires GITHUB_TOKEN (a classic PAT with no scopes is enough for public code search)")
    headers = {"Authorization": "token " + token, "Accept": "application/vnd.github+json"}
    domain = ctx.target.scope
    j = ctx.http.get_json("https://api.github.com/search/code?q=%s&per_page=30" % quote('"%s"' % domain),
                          headers=headers, timeout=25, retries=1)
    total = j.get("total_count", 0)
    hits = []
    for item in (j.get("items") or [])[:30]:
        repo = (item.get("repository") or {}).get("full_name")
        path = item.get("path")
        if repo and path:
            hits.append("%s:%s" % (repo, path))
    if hits:
        ctx.res.extras["github_code_hits"] = hits
        ctx.res.finding("low", "%d GitHub code result(s) mention \"%s\" (showing up to 30)" % (total, domain),
                       "; ".join(hits[:8]) + (" ..." if len(hits) > 8 else ""), "github")
    return "%d total code match(es)" % total


@module("virustotal", modes=("domain",), phase=1, keys=("VT_API_KEY",),
        desc="VirusTotal domain report — categories, reputation, detected subdomains")
def mod_virustotal(ctx):
    key = ctx.key("VT_API_KEY")
    if not key:
        raise SourceError("requires VT_API_KEY")
    headers = {"x-apikey": key}
    domain = ctx.target.scope
    j = ctx.http.get_json("https://www.virustotal.com/api/v3/domains/%s" % quote(domain), headers=headers, timeout=25, retries=1)
    attrs = (j.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal, total_eng = stats.get("malicious", 0), sum(stats.values()) or 0
    if mal:
        ctx.res.finding("high" if mal > 3 else "medium", "%d/%d VirusTotal engines flag this domain as malicious" %
                       (mal, total_eng), "", "virustotal")
    for cat in sorted(set((attrs.get("categories") or {}).values())):
        ctx.res.add_tech("Content category (VirusTotal)", cat, "", "virustotal")
    n = 0
    try:
        sub = ctx.http.get_json("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40" % quote(domain),
                                headers=headers, timeout=25, retries=1)
        for item in sub.get("data") or []:
            if ctx.res.add_host(item.get("id", ""), "virustotal"):
                n += 1
    except SourceError as e:
        ctx.warn("subdomains: %s" % e)
    return "reputation=%s, malicious=%d/%d engines, +%d subdomain(s)" % (attrs.get("reputation"), mal, total_eng, n)


@module("securitytrails", modes=("domain",), phase=1, keys=("SECURITYTRAILS_API_KEY",),
        desc="SecurityTrails — subdomain enumeration")
def mod_securitytrails(ctx):
    key = ctx.key("SECURITYTRAILS_API_KEY")
    if not key:
        raise SourceError("requires SECURITYTRAILS_API_KEY")
    domain = ctx.target.scope
    j = ctx.http.get_json("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false" % quote(domain),
                          headers={"APIKEY": key}, timeout=25, retries=1)
    subs = j.get("subdomains") or []
    for s in subs:
        ctx.res.add_host("%s.%s" % (s, domain) if s else domain, "securitytrails")
    return "%d subdomain(s)" % len(subs)


@module("shodan", modes=("domain", "ip"), phase=1, keys=("SHODAN_API_KEY",),
        desc="Shodan search API — banners, open ports and CVEs across every IP Shodan has tied to this target")
def mod_shodan(ctx):
    key = ctx.key("SHODAN_API_KEY")
    if not key:
        raise SourceError("requires SHODAN_API_KEY")
    q = "hostname:%s" % ctx.target.scope if ctx.target.kind == "domain" else "ip:%s" % ctx.target.ip
    j = ctx.http.get_json("https://api.shodan.io/shodan/host/search?key=%s&query=%s" % (key, quote(q)), timeout=25, retries=1)
    matches = j.get("matches") or []
    ips_seen = set()
    for m in matches:
        ip = m.get("ip_str")
        if not ip:
            continue
        ips_seen.add(ip)
        ctx.res.add_ip(ip, "shodan", host=(m.get("hostnames") or [None])[0])
        for h in m.get("hostnames") or []:
            ctx.file_hostname(h, "shodan")
        prod = m.get("product")
        if prod:
            ctx.res.add_tech("Service banner (Shodan)", "%s%s" % (prod, (" " + m["version"]) if m.get("version") else ""),
                             "%s:%s" % (ip, m.get("port")), "shodan")
        vulns = list((m.get("vulns") or {}).keys())
        if vulns:
            ctx.res.finding("high", "%s:%s has %d CVE(s) per Shodan" % (ip, m.get("port"), len(vulns)),
                           ", ".join(sorted(vulns)[:10]), "shodan")
    return "%d match(es) across %d IP(s), total reported=%d" % (len(matches), len(ips_seen), j.get("total", 0))


@module("fullhunt", modes=("domain",), phase=1, keys=("FULLHUNT_API_KEY",), desc="FullHunt — subdomain discovery")
def mod_fullhunt(ctx):
    key = ctx.key("FULLHUNT_API_KEY")
    if not key:
        raise SourceError("requires FULLHUNT_API_KEY")
    domain = ctx.target.scope
    j = ctx.http.get_json("https://fullhunt.io/api/v1/domain/%s/subdomains" % quote(domain),
                          headers={"X-API-KEY": key}, timeout=25, retries=1)
    hosts = j.get("hosts") or []
    for h in hosts:
        ctx.res.add_host(h, "fullhunt")
    return "%d hostname(s)" % len(hosts)


@module("chaos", modes=("domain",), phase=1, keys=("CHAOS_API_KEY",), desc="ProjectDiscovery Chaos — subdomain dataset")
def mod_chaos(ctx):
    key = ctx.key("CHAOS_API_KEY")
    if not key:
        raise SourceError("requires CHAOS_API_KEY")
    domain = ctx.target.scope
    j = ctx.http.get_json("https://dns.projectdiscovery.io/dns/%s/subdomains" % quote(domain),
                          headers={"Authorization": key}, timeout=25, retries=1)
    subs = j.get("subdomains") or []
    for s in subs:
        name = s if (s and s.endswith(domain)) else ("%s.%s" % (s, domain) if s else domain)
        ctx.res.add_host(name, "chaos")
    return "%d subdomain(s)" % len(subs)


# ============================================================================
# Shared per-IP enrichers — used both for a bare-IP target and for every IP
# discovered while scanning a domain (see the "ip-core" and "ip-enrich" modules)
# ============================================================================
def enrich_ip_rdap(ctx, ip):
    parsed = parse_rdap_ip(rdap_lookup(ctx, "ip", ip))
    ctx.res.ip_intel(ip)["rdap"] = parsed
    if parsed.get("abuse_email"):
        ctx.res.add_email(parsed["abuse_email"], "rdap-ip")
    for c in parsed.get("cidrs") or []:
        ctx.res.add_netblock(c, "rdap-ip")
    label = classify_holder(parsed.get("org") or parsed.get("name") or "")
    if label:
        ctx.res.add_tech("Network / hosting provider", label, parsed.get("org") or parsed.get("name") or "", "rdap-ip")


def enrich_ip_geo(ctx, ip):
    j = ctx.http.get_json("https://ipwho.is/%s" % ip, timeout=15, retries=1)
    if j.get("success") is False:
        raise SourceError("ipwho.is: %s" % j.get("message", "lookup failed"))
    conn = j.get("connection") or {}
    ctx.res.ip_intel(ip)["geo"] = {"country": j.get("country"), "region": j.get("region"), "city": j.get("city"),
                                   "latitude": j.get("latitude"), "longitude": j.get("longitude"),
                                   "asn": conn.get("asn"), "org": conn.get("org"), "isp": conn.get("isp"),
                                   "timezone": (j.get("timezone") or {}).get("id")}
    label = classify_holder(conn.get("org") or conn.get("isp") or "")
    if label:
        ctx.res.add_tech("Network / hosting provider", label, conn.get("org") or conn.get("isp") or "", "ipwho.is")


def enrich_ip_shodan_internetdb(ctx, ip):
    status, _, body = ctx.http.request("https://internetdb.shodan.io/%s" % ip, timeout=15, retries=1, ok_statuses=(200, 404))
    if status == 404:
        return
    j = parse_json(body)
    if "ports" not in j:
        return
    ctx.res.ip_intel(ip)["shodan_internetdb"] = j
    for h in j.get("hostnames") or []:
        ctx.file_hostname(h, "shodan-internetdb")
    ports = j.get("ports") or []
    risky = [p for p in ports if p in RISKY_PORTS]
    if risky:
        ctx.res.finding("medium", "%s exposes port(s) often restricted to internal use: %s" %
                       (ip, ", ".join("%d/%s" % (p, RISKY_PORTS[p]) for p in risky)),
                       "Observed via Shodan's internet-wide scan data, not probed by this tool.", "shodan-internetdb")
    vulns = j.get("vulns") or []
    if vulns:
        ctx.res.finding("high", "%s has %d CVE(s) associated with it in Shodan" % (ip, len(vulns)),
                       ", ".join(sorted(vulns)[:12]) + (" ..." if len(vulns) > 12 else ""), "shodan-internetdb")
    for cpe in j.get("cpes") or []:
        ctx.res.add_tech("Software (CPE, via Shodan)", cpe, "", "shodan-internetdb")


def enrich_ip_bgpview(ctx, ip):
    j = ctx.http.get_json("https://api.bgpview.io/ip/%s" % ip, timeout=20, retries=1)
    if j.get("status") != "ok":
        raise SourceError("bgpview.io: %s" % j.get("status_message", "lookup failed"))
    prefixes = (j.get("data") or {}).get("prefixes") or []
    ctx.res.ip_intel(ip)["bgpview"] = {"prefixes": [
        {"prefix": p.get("prefix"), "asn": (p.get("asn") or {}).get("asn"),
        "name": (p.get("asn") or {}).get("name"), "description": (p.get("asn") or {}).get("description"),
        "country": (p.get("asn") or {}).get("country_code")} for p in prefixes[:5]]}
    for p in prefixes[:5]:
        if p.get("prefix"):
            ctx.res.add_netblock(p["prefix"], "bgpview")
        asn = p.get("asn") or {}
        if asn.get("asn"):
            ctx.res.add_tech("ASN", "AS%s — %s" % (asn.get("asn"), asn.get("name") or asn.get("description") or ""), "", "bgpview")


def enrich_ip_ripestat(ctx, ip):
    j = ctx.http.get_json("https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=%s" % ip, timeout=20, retries=1)
    contacts = ((j.get("data") or {}).get("abuse_contacts")) or []
    if contacts:
        ctx.res.ip_intel(ip)["ripe_abuse_contacts"] = contacts
        for c in contacts:
            ctx.res.add_email(c, "ripestat")


def enrich_ip_greynoise(ctx, ip):
    key = ctx.key("GREYNOISE_API_KEY")
    headers = {"key": key} if key else {}
    status, _, body = ctx.http.request("https://api.greynoise.io/v3/community/%s" % ip, headers=headers,
                                       timeout=15, retries=1, ok_statuses=(200, 404))
    if status == 404:
        return
    j = parse_json(body)
    ctx.res.ip_intel(ip)["greynoise"] = {"noise": j.get("noise"), "riot": j.get("riot"),
                                         "classification": j.get("classification"), "name": j.get("name"),
                                         "last_seen": j.get("last_seen")}
    if j.get("classification") == "malicious":
        ctx.res.finding("high", "%s is classified 'malicious' by GreyNoise" % ip, j.get("name") or "", "greynoise")
    elif j.get("noise"):
        ctx.res.finding("info", "%s observed mass-scanning the internet (GreyNoise 'noise')" % ip, j.get("name") or "", "greynoise")


def enrich_ip_ptr(ctx, ip):
    rev = ipaddress.ip_address(ip).reverse_pointer
    ans = ctx.doh.query(rev, "PTR")
    ptr = [a["data"] for a in ans["answers"] if a["type"] == "PTR"]
    if not ptr:
        raise SourceError("no PTR record")
    ctx.res.ip_intel(ip)["ptr"] = ptr
    for h in ptr:
        ctx.res.add_related(h, "ptr")


IP_ENRICHERS = [enrich_ip_rdap, enrich_ip_geo, enrich_ip_shodan_internetdb, enrich_ip_bgpview,
               enrich_ip_ripestat, enrich_ip_greynoise, enrich_ip_ptr]


def run_ip_enrichers(ctx, ip):
    """Run every per-IP enricher against one IP, containing failures to the single enricher that
    caused them. A SourceError (network/HTTP/bad-payload) is the expected failure mode and is
    reported with a clean message; anything else (a parsing bug tripped by an unusual real-world
    response shape) is also contained here rather than being allowed to bubble up and mark every
    *other* IP in the same batch as failed too. Returns the list of per-enricher error strings."""
    errs = []
    for fn in IP_ENRICHERS:
        label = fn.__name__.replace("enrich_ip_", "")
        try:
            fn(ctx, ip)
        except SourceError as e:
            errs.append("%s: %s" % (label, e))
        except Exception as e:  # noqa: BLE001 - one source's bug must not sink this IP or any other
            errs.append("%s: %s: %s" % (label, type(e).__name__, e))
    return errs


@module("ip-core", modes=("ip",), phase=1,
        desc="RDAP, geolocation/ASN, Shodan InternetDB, BGP prefixes, abuse contacts, GreyNoise and reverse DNS for the target IP")
def mod_ip_core(ctx):
    ip = ctx.target.ip
    errs = run_ip_enrichers(ctx, ip)
    if len(errs) == len(IP_ENRICHERS):
        raise SourceError("; ".join(errs))
    for e in errs:
        ctx.warn(e)
    intel = ctx.res.ip_intel(ip)
    geo, sdb = intel.get("geo") or {}, intel.get("shodan_internetdb") or {}
    return "geo=%s, asn=%s, ptr=%s, shodan_open_ports=%d" % (
        geo.get("country"), geo.get("asn"), bool(intel.get("ptr")), len(sdb.get("ports", [])))


# ============================================================================
# Phase-2 modules: resolve everything phase 1 found, then enrich every IP
# ============================================================================
@module("resolve", modes=("domain",), phase=2,
        desc="Resolve every hostname collected above via public DNS resolvers (A/AAAA/CNAME) and flag suspicious dangling CNAMEs")
def mod_resolve(ctx):
    res, doh, modname = ctx.res, ctx.doh, _TLS.module
    pending = [h for h, rec in res.hosts.items() if rec["resolves"] is None]
    cap = ctx.args.max_resolve
    if len(pending) > cap:
        ctx.warn("%d hostnames collected; resolving the first %d (raise with --max-resolve)" % (len(pending), cap))
        pending = pending[:cap]
    lock = threading.Lock()
    counters = {"resolved": 0, "dangling": 0}

    def _resolve(name):
        _TLS.module = modname
        rec = res.hosts[name]
        try:
            a4 = doh.query(name, "A")
        except SourceError:
            return
        answers = list(a4["answers"])
        try:
            answers += doh.query(name, "AAAA")["answers"]
        except SourceError:
            pass
        with lock:
            rec["rcode"], rec["resolves"] = a4["rcode"], bool(answers) or a4["rcode"] == 0
        if not answers and a4["rcode"] == 3:
            cname = None
            try:
                cn = doh.query(name, "CNAME")
                if cn["answers"]:
                    cname = cn["answers"][0]["data"]
            except SourceError:
                pass
            if cname:
                with lock:
                    rec["cnames"].append(cname)
                svc, prone = match_service(cname)
                if svc:
                    res.add_tech("Hosting / platform", svc, cname, "resolve")
                if prone:
                    with lock:
                        counters["dangling"] += 1
                    res.finding("high", "Possible dangling CNAME: %s -> %s" % (name, cname),
                               "%s points to %s (a provider where unclaimed resources are sometimes reusable by a "
                               "third party) but the name does not currently resolve. If the %s resource behind it "
                               "was deleted, this can be a subdomain takeover; verify manually before treating it "
                               "as confirmed." % (name, cname, svc), "resolve")
            return
        with lock:
            counters["resolved"] += 1
        for a in answers:
            if a["type"] == "CNAME":
                with lock:
                    rec["cnames"].append(a["data"])
                svc, _p = match_service(a["data"])
                if svc:
                    res.add_tech("Hosting / platform", svc, a["data"], "resolve")
                res.add_related(a["data"], "resolve", via="CNAME of %s" % name)
            elif a["type"] in ("A", "AAAA"):
                res.add_ip(a["data"], "resolve", host=name, role=a["type"])

    if pending:
        with cf.ThreadPoolExecutor(max_workers=30) as ex:
            list(ex.map(_resolve, pending))
    return "%d/%d hostnames resolve; %d flagged as possibly-dangling CNAMEs" % (
        counters["resolved"], len(pending), counters["dangling"])


@module("ip-enrich", modes=("domain",), phase=2,
        desc="RDAP/ASN/geo/Shodan/abuse-contact/GreyNoise/PTR for every unique IP discovered above")
def mod_ip_enrich(ctx):
    modname = _TLS.module
    cap = ctx.args.max_ips
    ips = list(ctx.res.ips.keys())
    if len(ips) > cap:
        ctx.warn("%d unique IPs discovered; enriching the first %d (raise with --max-ips)" % (len(ips), cap))
        ips = ips[:cap]
    lock = threading.Lock()
    done = {"n": 0}

    def _one(ip):
        _TLS.module = modname
        errs = run_ip_enrichers(ctx, ip)
        for e in errs:
            ctx.warn("%s: %s" % (ip, e))
        if len(errs) < len(IP_ENRICHERS):
            with lock:
                done["n"] += 1

    if not ips:
        return "no IPs were discovered to enrich"
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(_one, ips))
    return "enriched %d/%d unique IP address(es)" % (done["n"], len(ips))


# ============================================================================
# Phase-3 module: dork-query generation (+ optional live search via a key)
# ============================================================================
def build_dorks(target):
    d, ip, out = target.scope, target.ip, defaultdict(list)
    if target.kind == "domain":
        out["Google / Bing — general"] = [
            "site:%s" % d, "site:%s -www" % d, "site:*.%s" % d,
            'site:%s intitle:"index of"' % d, "site:%s ext:pdf" % d,
            "site:%s ext:xlsx OR ext:csv OR ext:doc OR ext:docx" % d,
        ]
        out["Exposed files & secrets"] = [
            "site:%s ext:env OR ext:log OR ext:bak OR ext:sql OR ext:config" % d,
            "site:%s inurl:wp-config OR inurl:.git OR inurl:.svn" % d,
            'site:%s "api_key" OR "apikey" OR "secret_key"' % d,
            'site:pastebin.com "%s"' % d, 'site:github.com "%s" password OR secret OR api_key' % d,
        ]
        out["Login & admin surfaces"] = [
            "site:%s inurl:login OR inurl:admin OR inurl:portal OR inurl:dashboard" % d,
            'site:%s intitle:"login" OR intitle:"sign in"' % d,
        ]
        out["Error messages / stack traces"] = [
            'site:%s "Warning:" "on line"' % d, 'site:%s "stack trace"' % d, 'site:%s "SQL syntax" OR "mysql_fetch"' % d,
        ]
        out["Cached / historical"] = ["site:web.archive.org/web/*/%s*" % d]
        out["Shodan"] = ['hostname:"%s"' % d, 'ssl.cert.subject.cn:"%s"' % d, 'http.html:"%s"' % d]
        out["Censys"] = ["names: %s" % d, 'services.tls.certificates.leaf_data.subject.common_name: "%s"' % d]
        out["GitHub code search"] = ['"%s" password' % d, '"%s" api_key' % d, '"%s" secret' % d, '"@%s" filename:.env' % d]
        out["LinkedIn / people"] = ['site:linkedin.com/in "%s"' % d, 'site:linkedin.com/company "%s"' % d]
        out["Job postings (tech-stack leakage)"] = ['site:linkedin.com/jobs "%s"' % d, '"%s" site:indeed.com' % d]
    else:
        out["Shodan"] = ["ip:%s" % ip]
        out["Censys"] = ["ip: %s" % ip]
        out["Google / Bing"] = ['"%s"' % ip]
    return out


@module("dorks", modes=("domain", "ip"), phase=3,
        desc="Search-engine / Shodan / Censys / GitHub dork queries, optionally executed live via a search-API key")
def mod_dorks(ctx):
    ctx.res.dorks = build_dorks(ctx.target)
    n = sum(len(v) for v in ctx.res.dorks.values())
    brave, serp = ctx.key("BRAVE_API_KEY"), ctx.key("SERPAPI_KEY")
    gkey, gcx = ctx.key("GOOGLE_CSE_KEY"), ctx.key("GOOGLE_CSE_CX")
    if not (brave or serp or (gkey and gcx)):
        return "%d dork queries generated (set BRAVE_API_KEY / SERPAPI_KEY / GOOGLE_CSE_KEY+GOOGLE_CSE_CX to auto-run a sample)" % n
    sample = [q for cat, qs in ctx.res.dorks.items()
             if any(k in cat for k in ("Google", "Bing", "Exposed", "Login")) for q in qs][:6]
    engine, results, live_hits = None, {}, 0
    try:
        for q in sample:
            hits = []
            if brave:
                engine = "Brave Search API"
                j = ctx.http.get_json("https://api.search.brave.com/res/v1/web/search?q=%s&count=5" % quote(q),
                                      headers={"X-Subscription-Token": brave, "Accept": "application/json"}, timeout=20, retries=1)
                hits = [{"title": r.get("title"), "url": r.get("url")} for r in (j.get("web") or {}).get("results") or []]
            elif serp:
                engine = "SerpApi"
                j = ctx.http.get_json("https://serpapi.com/search.json?engine=google&num=5&q=%s&api_key=%s" % (quote(q), serp),
                                      timeout=20, retries=1)
                hits = [{"title": r.get("title"), "url": r.get("link")} for r in j.get("organic_results") or []]
            else:
                engine = "Google Programmable Search"
                j = ctx.http.get_json("https://www.googleapis.com/customsearch/v1?key=%s&cx=%s&num=5&q=%s" % (gkey, gcx, quote(q)),
                                      timeout=20, retries=1)
                hits = [{"title": r.get("title"), "url": r.get("link")} for r in j.get("items") or []]
            if hits:
                results[q] = hits
                live_hits += len(hits)
                for h in hits:
                    ctx.res.add_url(h.get("url", ""), "dork-" + engine)
    except SourceError as e:
        ctx.warn("live dork search via %s: %s" % (engine, e))
    ctx.res.extras["dork_live_results"] = results
    return "%d dork queries generated; %d live result(s) fetched via %s" % (n, live_hits, engine)


# ============================================================================
# Orchestrator
# ============================================================================
def run_module(ctx, name):
    spec = MODULES[name]
    _TLS.module = name
    t0 = time.monotonic()
    ctx.res.set_status(name, "running")
    ctx.log.info("  -> %s" % name)
    try:
        note = spec["fn"](ctx)
        ctx.res.set_status(name, "ok", note or "done", time.monotonic() - t0)
        ctx.log.debug("     %s ok: %s" % (name, note))
    except SourceError as e:
        ctx.res.set_status(name, "failed", str(e), time.monotonic() - t0)
        ctx.log.debug("     %s FAILED: %s" % (name, e))
    except Exception as e:  # noqa: BLE001 - one module's bug must not sink the whole scan
        ctx.res.set_status(name, "error", "%s: %s" % (type(e).__name__, e), time.monotonic() - t0)
        ctx.log.debug("     %s ERRORED:\n%s" % (name, traceback.format_exc()))
    finally:
        _TLS.module = None


def select_modules(target_kind, only, skip, keys):
    names = [n for n, s in MODULES.items() if target_kind in s["modes"]]
    if only:
        wanted = set(only)
        unknown = wanted - set(MODULES)
        if unknown:
            raise SystemExit("unknown module(s): %s\navailable: %s" % (", ".join(sorted(unknown)), ", ".join(sorted(MODULES))))
        names = [n for n in names if n in wanted]
    if skip:
        names = [n for n in names if n not in set(skip)]
    runnable, need_keys = [], []
    for n in names:
        need = MODULES[n]["keys"]
        if need and not any(keys.get(k) for k in need):
            need_keys.append((n, "needs one of: " + ", ".join(need)))
        else:
            runnable.append(n)
    return runnable, need_keys


def run_scan(ctx):
    runnable, need_keys = select_modules(ctx.target.kind, ctx.args.only, ctx.args.skip, ctx.keys)
    for n, why in need_keys:
        ctx.res.set_status(n, "skipped", why)
    by_phase = defaultdict(list)
    for n in runnable:
        by_phase[MODULES[n]["phase"]].append(n)
    workers = max(1, ctx.args.workers)
    for phase in sorted(by_phase):
        names = by_phase[phase]
        if not names:
            continue
        ctx.log.info("[*] phase %d: %s" % (phase, ", ".join(sorted(names))))
        if len(names) == 1 or workers == 1:
            for n in names:
                run_module(ctx, n)
        else:
            with cf.ThreadPoolExecutor(max_workers=min(workers, len(names))) as ex:
                list(ex.map(lambda n: run_module(ctx, n), names))
    return runnable


# ============================================================================
# Report assembly
# ============================================================================
def result_to_dict(ctx, runnable, elapsed, args):
    res, t = ctx.res, ctx.target
    hosts = {h: {"sources": sorted(r["sources"]), "ips": sorted(r["ips"]), "cnames": sorted(set(r["cnames"])),
                "resolves": r["resolves"]} for h, r in sorted(res.hosts.items())}
    ips = {ip: {"sources": sorted(r["sources"]), "hosts": sorted(r["hosts"]), "roles": sorted(r["roles"]),
               "intel": r["intel"]} for ip, r in sorted(res.ips.items())}
    findings = sorted(res.findings, key=lambda f: SEV_RANK.get(f["severity"], 9))
    return {
        "tool": "passive_recon.py", "version": __version__, "generated_at": utcnow().isoformat(),
        "elapsed_seconds": round(elapsed, 1),
        "target": {"input": t.raw, "kind": t.kind, "resolved_host": t.host, "scope": t.scope},
        "modules_run": sorted(runnable), "module_status": res.status,
        "summary": {"hosts": len(hosts), "ips": len(ips), "urls": len(res.urls), "urls_dropped": res.urls_dropped,
                   "emails": len(res.emails), "related_domains": len(res.related), "netblocks": len(res.netblocks),
                   "findings": len(findings), "technologies": len(res.tech)},
        "findings": findings, "hosts": hosts, "ips": ips,
        "urls": {u: v for u, v in list(res.urls.items())[:args.max_urls]},
        "emails": {e: sorted(s) for e, s in sorted(res.emails.items())},
        "related_domains": {dm: {"sources": sorted(v["sources"]), "via": v["via"]} for dm, v in sorted(res.related.items())},
        "netblocks": {n: sorted(s) for n, s in sorted(res.netblocks.items())},
        "dns": res.dns, "whois": res.whois, "certificates": res.certs,
        "technologies": res.tech, "extras": res.extras, "dorks": res.dorks,
    }


def ip_summary_bits(intel):
    """One-line human summary of everything collected for an IP, with fallbacks so a partial
    enrichment (e.g. geo/RDAP rate-limited but bgpview/RIPEstat still came through) still shows
    something instead of a misleading '(no enrichment data)'."""
    geo, rdap = intel.get("geo") or {}, intel.get("rdap") or {}
    sdb, bgp, gn = intel.get("shodan_internetdb") or {}, intel.get("bgpview") or {}, intel.get("greynoise") or {}
    bits = []
    if geo.get("country"):
        bits.append("%s, %s" % (geo.get("city") or "?", geo["country"]))
    asn_org = geo.get("org") or geo.get("isp")
    if geo.get("asn"):
        bits.append("AS%s %s" % (geo["asn"], asn_org or ""))
    elif bgp.get("prefixes"):
        p0 = bgp["prefixes"][0]
        if p0.get("asn"):
            bits.append("AS%s %s" % (p0["asn"], p0.get("name") or p0.get("description") or ""))
    if rdap.get("org") and rdap["org"] != asn_org:
        bits.append("RDAP org: %s" % rdap["org"])
    if sdb.get("ports"):
        bits.append("open ports: %s" % ", ".join(map(str, sorted(sdb["ports"]))))
    if gn.get("classification"):
        bits.append("GreyNoise: %s" % gn["classification"])
    abuse = rdap.get("abuse_email") or (intel.get("ripe_abuse_contacts") or [None])[0]
    if abuse:
        bits.append("abuse contact: %s" % abuse)
    return bits


def render_markdown(d):
    L, t, s = [], d["target"], d["summary"]
    L.append("# Passive recon report: %s\n" % t["input"])
    L.append("Generated %s UTC in %ss — target type **%s**, scope `%s`\n" %
            (d["generated_at"][:19].replace("T", " "), d["elapsed_seconds"], t["kind"], t["scope"]))
    L.append("## Summary\n")
    L.append("| Hosts | IPs | URLs | Emails | Related domains | Netblocks | Findings | Technologies |")
    L.append("|---|---|---|---|---|---|---|---|")
    L.append("| %d | %d | %d%s | %d | %d | %d | %d | %d |\n" % (
        s["hosts"], s["ips"], s["urls"], (" (+%d dropped)" % s["urls_dropped"] if s["urls_dropped"] else ""),
        s["emails"], s["related_domains"], s["netblocks"], s["findings"], s["technologies"]))

    ok = sorted(n for n, v in d["module_status"].items() if v["status"] == "ok")
    bad = sorted((n, v) for n, v in d["module_status"].items() if v["status"] in ("failed", "error"))
    skipped = sorted((n, v) for n, v in d["module_status"].items() if v["status"] == "skipped")
    partial = sorted((n, v) for n, v in d["module_status"].items() if v["status"] == "ok" and v.get("warnings"))
    L.append("**Sources queried (%d ok / %d failed / %d skipped):** %s\n" % (len(ok), len(bad), len(skipped), ", ".join(ok)))
    if bad:
        L.append("<details><summary>Sources that failed (%d)</summary>\n" % len(bad))
        for n, v in bad:
            L.append("- **%s**: %s" % (n, v["message"]))
        L.append("</details>\n")
    if skipped:
        L.append("<details><summary>Sources skipped — missing API key (%d)</summary>\n" % len(skipped))
        for n, v in skipped:
            L.append("- **%s**: %s" % (n, v["message"]))
        L.append("</details>\n")
    if partial:
        L.append("<details><summary>Sources that succeeded overall but hit some individual errors (%d)</summary>\n" % len(partial))
        for n, v in partial:
            L.append("- **%s** (%s): %s" % (n, v["message"], "; ".join(v["warnings"])))
        L.append("</details>\n")

    if d["findings"]:
        L.append("## Findings\n")
        for f in d["findings"]:
            L.append("- **[%s]** %s%s _(source: %s)_" % (f["severity"].upper(), f["title"],
                     ("  \n  " + f["detail"]) if f["detail"] else "", f["source"]))
        L.append("")

    if d["technologies"]:
        L.append("## Technology & vendor fingerprint\n")
        by_cat = defaultdict(set)
        for te in d["technologies"]:
            by_cat[te["category"]].add(te["name"])
        for cat in sorted(by_cat):
            L.append("- **%s:** %s" % (cat, ", ".join(sorted(by_cat[cat]))))
        L.append("")

    if d["whois"]:
        L.append("## Domain registration (RDAP)\n")
        for dom, w in d["whois"].items():
            L.append("**%s**" % dom)
            L.append("- Statuses: %s" % (", ".join(w.get("statuses") or []) or "-"))
            L.append("- Events: " + ("; ".join("%s=%s" % (k, v) for k, v in (w.get("events") or {}).items()) or "-"))
            L.append("- Nameservers: %s" % ", ".join(w.get("nameservers") or []))
            L.append("- DNSSEC: %s" % w.get("dnssec"))
            for e in w.get("entities") or []:
                if e.get("org") or e.get("name") or e.get("email"):
                    L.append("- %s: %s" % ("/".join(e.get("roles") or []),
                             " / ".join(x for x in (e.get("org"), e.get("name"), e.get("email")) if x)))
            L.append("")

    dns_nonempty = {dom: rec for dom, rec in d["dns"].items() if rec}
    if dns_nonempty:
        L.append("## DNS\n")
        for dom, rec in dns_nonempty.items():
            L.append("**%s**" % dom)
            for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA"):
                if rec.get(rtype):
                    L.append("- %s: %s" % (rtype, "; ".join(rec[rtype])))
            if rec.get("wildcard"):
                L.append("- Wildcard DNS -> %s" % ", ".join(rec["wildcard"]))
            if rec.get("dmarc"):
                L.append("- DMARC: `%s`" % rec["dmarc"])
            if rec.get("dkim_selectors"):
                L.append("- DKIM selectors found: %s" % ", ".join(rec["dkim_selectors"]))
            L.append("")

    if d["certificates"]:
        L.append("## Certificate transparency\n")
        for src, c in d["certificates"].items():
            L.append("- **%s:** %s" % (src, ", ".join("%s=%s" % (k, v) for k, v in c.items() if k != "top_issuers")))
            if c.get("top_issuers"):
                L.append("  top issuers: " + ", ".join("%s (%d)" % tuple(kv) for kv in c["top_issuers"]))
        L.append("")

    if d["hosts"]:
        L.append("## Hosts (%d)\n" % len(d["hosts"]))
        L.append("| Host | Resolves | IP(s) | CNAME | Sources |")
        L.append("|---|---|---|---|---|")
        items = list(d["hosts"].items())
        for h, r in items[:1000]:
            L.append("| %s | %s | %s | %s | %s |" % (h, r["resolves"], ", ".join(r["ips"][:4]),
                     ", ".join(r["cnames"][:2]), ", ".join(sorted(r["sources"]))))
        if len(items) > 1000:
            L.append("\n_... %d more host(s) in the JSON report._" % (len(items) - 1000))
        L.append("")

    if d["ips"]:
        L.append("## IP addresses (%d)\n" % len(d["ips"]))
        for ip, r in d["ips"].items():
            bits = ip_summary_bits(r["intel"])
            L.append("**%s**  " % ip)
            L.append("  " + (" · ".join(bits) if bits else "(no enrichment data)"))
            if r["hosts"]:
                L.append("  hostnames: %s" % ", ".join(sorted(r["hosts"])[:10]))
            L.append("")

    if d["related_domains"]:
        L.append("## Related / third-party domains (%d)\n" % len(d["related_domains"]))
        L.append(", ".join(sorted(d["related_domains"])[:300]))
        L.append("")

    if d["emails"]:
        L.append("## Email addresses observed (%d)\n" % len(d["emails"]))
        for e in sorted(d["emails"]):
            L.append("- %s _(%s)_" % (e, ", ".join(d["emails"][e])))
        L.append("")

    if d["netblocks"]:
        L.append("## Netblocks (%d)\n" % len(d["netblocks"]))
        try:
            nb_sorted = sorted(d["netblocks"], key=lambda c: ipaddress.ip_network(c).num_addresses)
        except ValueError:
            nb_sorted = sorted(d["netblocks"])
        L.append(", ".join(nb_sorted[:200]))
        L.append("")

    extras = d.get("extras", {})
    if extras.get("robots_disallow"):
        L.append("## Archived robots.txt — Disallow paths\n")
        L.append(", ".join(extras["robots_disallow"]))
        L.append("")
    if extras.get("page_titles"):
        L.append("## Page titles seen (urlscan.io)\n")
        for ti in extras["page_titles"][:10]:
            L.append("- %s" % ti)
        L.append("")
    if extras.get("m365_tenant"):
        L.append("## Microsoft 365 / Entra ID tenant\n")
        L.append("```\n%s\n```\n" % json.dumps(extras["m365_tenant"], indent=2))
    if extras.get("github_code_hits"):
        L.append("## GitHub code search hits\n")
        for h in extras["github_code_hits"]:
            L.append("- %s" % h)
        L.append("")

    if d["urls"]:
        shown = list(d["urls"])[:300]
        L.append("## Sample of archived/observed URLs (%d of %d shown)\n" % (len(shown), len(d["urls"])))
        for u in shown:
            L.append("- %s" % u)
        L.append("")

    if d["dorks"]:
        L.append("## Dork queries (for manual follow-up in Google / Shodan / Censys / GitHub)\n")
        for cat, qs in d["dorks"].items():
            L.append("**%s**" % cat)
            for q in qs:
                L.append("- `%s`" % q)
            L.append("")
        live = extras.get("dork_live_results")
        if live:
            L.append("### Live search results\n")
            for q, hits in live.items():
                L.append("`%s`" % q)
                for h in hits:
                    L.append("- [%s](%s)" % (h.get("title") or h.get("url"), h.get("url")))
                L.append("")

    L.append("---\n*Passive recon only: everything above came from third-party indexes, archives and public "
             "registries. No request was ever sent to the target's own servers.*")
    return "\n".join(L)


def esc(s):
    return htmllib.escape(str(s), quote=True)


# Kept as a plain constant (never used as a %-format template) so the braces
# and percent signs CSS is full of never need escaping.
HTML_CSS = """
:root{--bg:#0b0d12;--panel:#12151c;--line:#232733;--text:#e6e9ef;--dim:#8a94a6;--accent:#5fb3ff;
--high:#ff5a6e;--med:#ffb84d;--low:#6fd0ff;--info:#8a94a6}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{padding:28px 20px 18px;border-bottom:1px solid var(--line)}
h1{margin:0 0 4px;font-size:22px}
h2{font-size:17px;border-top:1px solid var(--line);padding-top:18px;margin-top:28px}
.meta{color:var(--dim);font-size:13px}
main{max-width:980px;margin:0 auto;padding:8px 20px 60px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:22px}
.card span{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin:10px 0}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase}
tr:hover td{background:#161a23}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.03em}
.sev-high{background:#3a1420;color:var(--high)}
.sev-med{background:#3a2c12;color:var(--med)}
.sev-low{background:#0f2a36;color:var(--low)}
.sev-info{background:#1a1d26;color:var(--info)}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);
border-radius:8px;padding:10px 14px;margin:8px 0}
.finding.sh{border-left-color:var(--high)}
.finding.sm{border-left-color:var(--med)}
.finding.sl{border-left-color:var(--low)}
.finding .detail{color:var(--dim);font-size:13px;margin-top:4px}
details{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:8px 0}
summary{cursor:pointer;font-weight:600}
.tag{display:inline-block;background:#1a1e29;border:1px solid var(--line);border-radius:6px;
padding:2px 8px;margin:2px;font-size:12.5px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.dim{color:var(--dim)}
.small{font-size:12px}
footer{color:var(--dim);font-size:12px;text-align:center;padding:30px 20px;border-top:1px solid var(--line)}
"""


def render_html(d):
    t, s = d["target"], d["summary"]
    sev_class = {"high": "sev-high", "medium": "sev-med", "low": "sev-low", "info": "sev-info"}
    sev_border = {"high": "sh", "medium": "sm", "low": "sl", "info": ""}
    p = []
    p.append('<!doctype html><html lang="en"><head><meta charset="utf-8">'
             '<meta name="viewport" content="width=device-width, initial-scale=1">'
             "<title>Passive recon: %s</title><style>%s</style></head><body>"
             % (esc(t["input"]), HTML_CSS))
    p.append('<header><h1>Passive recon: %s</h1><div class="meta">Generated %s UTC &middot; %ss elapsed &middot; '
             'target type <b>%s</b> &middot; scope <code>%s</code></div></header><main>'
             % (esc(t["input"]), esc(d["generated_at"][:19].replace("T", " ")), esc(d["elapsed_seconds"]),
                esc(t["kind"]), esc(t["scope"])))

    p.append('<div class="grid">')
    for label, key in [("Hosts", "hosts"), ("IPs", "ips"), ("URLs", "urls"), ("Emails", "emails"),
                       ("Related domains", "related_domains"), ("Netblocks", "netblocks"),
                       ("Findings", "findings"), ("Technologies", "technologies")]:
        p.append('<div class="card"><b>%s</b><span>%s</span></div>' % (s[key], esc(label)))
    p.append("</div>")

    ok = sorted(n for n, v in d["module_status"].items() if v["status"] == "ok")
    bad = sorted((n, v) for n, v in d["module_status"].items() if v["status"] in ("failed", "error"))
    skipped = sorted((n, v) for n, v in d["module_status"].items() if v["status"] == "skipped")
    partial = sorted((n, v) for n, v in d["module_status"].items() if v["status"] == "ok" and v.get("warnings"))
    p.append("<p class='dim small'>Sources queried: <b>%d ok</b>, %d failed, %d skipped &mdash; %s</p>" %
            (len(ok), len(bad), len(skipped), "".join('<span class="tag">%s</span>' % esc(n) for n in ok)))
    if bad:
        p.append("<details><summary>Sources that failed (%d)</summary><table>" % len(bad))
        for n, v in bad:
            p.append("<tr><td class='mono'>%s</td><td class='dim'>%s</td></tr>" % (esc(n), esc(v["message"])))
        p.append("</table></details>")
    if skipped:
        p.append("<details><summary>Skipped — missing API key (%d)</summary><table>" % len(skipped))
        for n, v in skipped:
            p.append("<tr><td class='mono'>%s</td><td class='dim'>%s</td></tr>" % (esc(n), esc(v["message"])))
        p.append("</table></details>")
    if partial:
        p.append("<details><summary>Succeeded overall but hit some individual errors (%d)</summary><table>" % len(partial))
        for n, v in partial:
            p.append("<tr><td class='mono'>%s</td><td class='dim small'>%s<br>%s</td></tr>" %
                    (esc(n), esc(v["message"]), esc("; ".join(v["warnings"]))))
        p.append("</table></details>")

    if d["findings"]:
        p.append("<h2>Findings</h2>")
        for f in d["findings"]:
            p.append('<div class="finding %s"><span class="pill %s">%s</span>&nbsp; %s%s</div>' % (
                sev_border.get(f["severity"], ""), sev_class.get(f["severity"], "sev-info"), esc(f["severity"].upper()),
                esc(f["title"]), ('<div class="detail">%s &mdash; source: %s</div>' % (esc(f["detail"]), esc(f["source"])))
                if f["detail"] else ('<div class="detail">source: %s</div>' % esc(f["source"]))))

    if d["technologies"]:
        p.append("<h2>Technology &amp; vendor fingerprint</h2>")
        by_cat = defaultdict(set)
        for te in d["technologies"]:
            by_cat[te["category"]].add(te["name"])
        for cat in sorted(by_cat):
            p.append("<p><b>%s</b><br>%s</p>" % (esc(cat),
                    "".join('<span class="tag">%s</span>' % esc(n) for n in sorted(by_cat[cat]))))

    if d["whois"]:
        p.append("<h2>Domain registration (RDAP)</h2>")
        for dom, w in d["whois"].items():
            p.append("<p><b>%s</b><br>Statuses: %s<br>Events: %s<br>Nameservers: %s<br>DNSSEC: %s</p>" % (
                esc(dom), esc(", ".join(w.get("statuses") or []) or "-"),
                esc("; ".join("%s=%s" % (k, v) for k, v in (w.get("events") or {}).items()) or "-"),
                esc(", ".join(w.get("nameservers") or []) or "-"), esc(w.get("dnssec"))))
            rows = [e for e in (w.get("entities") or []) if e.get("org") or e.get("name") or e.get("email")]
            if rows:
                p.append("<table><tr><th>Role</th><th>Name / Org</th><th>Email</th></tr>")
                for e in rows:
                    p.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                        esc("/".join(e.get("roles") or [])), esc(e.get("org") or e.get("name") or "-"),
                        esc(e.get("email") or "-")))
                p.append("</table>")

    dns_nonempty = {dom: rec for dom, rec in d["dns"].items() if rec}
    if dns_nonempty:
        p.append("<h2>DNS</h2>")
        for dom, rec in dns_nonempty.items():
            p.append("<p><b>%s</b></p><table>" % esc(dom))
            for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA"):
                if rec.get(rtype):
                    p.append("<tr><td class='mono dim'>%s</td><td class='mono'>%s</td></tr>" % (rtype, esc("; ".join(rec[rtype]))))
            if rec.get("dmarc"):
                p.append("<tr><td class='mono dim'>DMARC</td><td class='mono'>%s</td></tr>" % esc(rec["dmarc"]))
            if rec.get("wildcard"):
                p.append("<tr><td class='mono dim'>Wildcard</td><td class='mono'>%s</td></tr>" % esc(", ".join(rec["wildcard"])))
            if rec.get("dkim_selectors"):
                p.append("<tr><td class='mono dim'>DKIM selectors</td><td class='mono'>%s</td></tr>" %
                        esc(", ".join(rec["dkim_selectors"])))
            p.append("</table>")

    if d["certificates"]:
        p.append("<h2>Certificate transparency</h2><table><tr><th>Source</th><th>Stats</th></tr>")
        for src, c in d["certificates"].items():
            stats = ", ".join("%s=%s" % (k, v) for k, v in c.items() if k != "top_issuers")
            if c.get("top_issuers"):
                stats += "; top issuers: " + ", ".join("%s (%d)" % tuple(kv) for kv in c["top_issuers"])
            p.append("<tr><td>%s</td><td>%s</td></tr>" % (esc(src), esc(stats)))
        p.append("</table>")

    if d["hosts"]:
        items = list(d["hosts"].items())
        p.append("<h2>Hosts (%d)</h2><table><tr><th>Host</th><th>Resolves</th><th>IP(s)</th><th>CNAME</th><th>Sources</th></tr>"
                % len(items))
        for h, r in items[:1500]:
            p.append("<tr><td class='mono'>%s</td><td>%s</td><td class='mono'>%s</td><td class='mono'>%s</td>"
                    "<td class='small dim'>%s</td></tr>" % (esc(h), r["resolves"], esc(", ".join(r["ips"][:4])),
                    esc(", ".join(r["cnames"][:2])), esc(", ".join(sorted(r["sources"])))))
        p.append("</table>")
        if len(items) > 1500:
            p.append("<p class='dim small'>+%d more in the JSON report.</p>" % (len(items) - 1500))

    if d["ips"]:
        p.append("<h2>IP addresses (%d)</h2>" % len(d["ips"]))
        for ip, r in d["ips"].items():
            bits = [esc(b) for b in ip_summary_bits(r["intel"])] or ["<span class='dim'>no enrichment data</span>"]
            p.append('<details><summary class="mono">%s &nbsp;<span class="dim small">%s</span></summary>'
                    '<p class="small">hostnames: %s<br>sources: %s</p></details>' % (
                        esc(ip), " &middot; ".join(bits), esc(", ".join(sorted(r["hosts"])[:15]) or "-"),
                        esc(", ".join(sorted(r["sources"])))))

    if d["related_domains"]:
        p.append("<h2>Related / third-party domains (%d)</h2><p>%s</p>" % (
            len(d["related_domains"]), "".join('<span class="tag">%s</span>' % esc(x)
                                              for x in sorted(d["related_domains"])[:300])))

    if d["emails"]:
        p.append("<h2>Email addresses observed (%d)</h2><table>" % len(d["emails"]))
        for e in sorted(d["emails"]):
            p.append("<tr><td class='mono'>%s</td><td class='dim small'>%s</td></tr>" % (esc(e), esc(", ".join(d["emails"][e]))))
        p.append("</table>")

    if d["netblocks"]:
        try:
            nb_sorted = sorted(d["netblocks"], key=lambda c: ipaddress.ip_network(c).num_addresses)
        except ValueError:
            nb_sorted = sorted(d["netblocks"])
        p.append("<h2>Netblocks (%d)</h2><p>%s</p>" % (len(d["netblocks"]),
                "".join('<span class="tag mono">%s</span>' % esc(c) for c in nb_sorted[:200])))

    extras = d.get("extras", {})
    if extras.get("robots_disallow"):
        p.append("<h2>Archived robots.txt &mdash; Disallow paths</h2><p>%s</p>" %
                "".join('<span class="tag mono">%s</span>' % esc(pa) for pa in extras["robots_disallow"]))
    if extras.get("page_titles"):
        p.append("<h2>Page titles seen (urlscan.io)</h2><ul>%s</ul>" %
                "".join("<li>%s</li>" % esc(ti) for ti in extras["page_titles"][:10]))
    if extras.get("m365_tenant"):
        mt = extras["m365_tenant"]
        p.append("<h2>Microsoft 365 / Entra ID tenant</h2><p>%s</p>" % esc(
            ", ".join("%s=%s" % (k, v) for k, v in mt.items() if v)))
    if extras.get("github_code_hits"):
        p.append("<h2>GitHub code search hits</h2><ul>%s</ul>" %
                "".join("<li class='mono small'>%s</li>" % esc(h) for h in extras["github_code_hits"]))

    if d["urls"]:
        shown = list(d["urls"])[:300]
        p.append("<h2>Sample of archived/observed URLs (%d of %d)</h2>"
                "<details open><summary>Show / hide</summary><p class='small mono'>%s</p></details>" % (
                    len(shown), len(d["urls"]),
                    "<br>".join('<a href="%s" rel="noopener">%s</a>' % (esc(u), esc(u)) for u in shown)))

    if d["dorks"]:
        p.append("<h2>Dork queries</h2><p class='dim small'>For manual follow-up in Google / Shodan / Censys / GitHub.</p>")
        for cat, qs in d["dorks"].items():
            p.append("<details><summary>%s (%d)</summary><p class='mono small'>%s</p></details>" %
                    (esc(cat), len(qs), "<br>".join(esc(q) for q in qs)))
        live = extras.get("dork_live_results")
        if live:
            p.append("<h3>Live search results</h3>")
            for q, hits in live.items():
                p.append("<p class='mono small dim'>%s</p><ul>%s</ul>" % (esc(q), "".join(
                    '<li><a href="%s">%s</a></li>' % (esc(h.get("url", "")), esc(h.get("title") or h.get("url")))
                    for h in hits)))

    p.append('</main><footer>Passive recon only &mdash; everything above came from third-party indexes, archives '
             "and public registries. No request was ever sent to the target's own servers.<br>"
             "Generated by passive_recon.py v%s</footer></body></html>" % esc(__version__))
    return "".join(p)


# ============================================================================
# CLI
# ============================================================================
KEY_NAMES = ["VT_API_KEY", "SECURITYTRAILS_API_KEY", "SHODAN_API_KEY", "GITHUB_TOKEN", "FULLHUNT_API_KEY",
            "CHAOS_API_KEY", "URLSCAN_API_KEY", "OTX_API_KEY", "CERTSPOTTER_API_KEY", "GREYNOISE_API_KEY",
            "BRAVE_API_KEY", "SERPAPI_KEY", "GOOGLE_CSE_KEY", "GOOGLE_CSE_CX"]


def load_keys(keys_file):
    keys = {k: os.environ.get(k, "") for k in KEY_NAMES}
    if keys_file:
        with open(keys_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k in KEY_NAMES:
                    keys[k] = v.strip().strip('"\'')
    return {k: v for k, v in keys.items() if v}


def build_arg_parser():
    ap = argparse.ArgumentParser(prog="passive_recon.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="domain, URL or IP address, e.g. example.com / https://example.com/path / 203.0.113.10")
    ap.add_argument("-o", "--outdir", default=None, help="output directory (default: ./recon_<target>_<timestamp>/)")
    ap.add_argument("--formats", default="json,md,html", help="comma-separated: json,md,html (default: all three)")
    ap.add_argument("--only", help="comma-separated list of modules to run (see --list-modules)")
    ap.add_argument("--skip", help="comma-separated list of modules to skip")
    ap.add_argument("--keys-file", help="path to a KEY=VALUE file with API keys (see the file header for names)")
    ap.add_argument("--exact", action="store_true",
                    help="treat the given hostname as the exact scope instead of rolling up to its registrable domain")
    ap.add_argument("--workers", type=int, default=8, help="max concurrent modules per phase (default: 8)")
    ap.add_argument("--timeout", type=int, default=25, help="per-request timeout in seconds (default: 25)")
    ap.add_argument("--retries", type=int, default=2, help="retries for transient/HTTP 429/5xx errors (default: 2)")
    ap.add_argument("--max-urls", type=int, default=15000, help="cap on distinct in-scope URLs kept (default: 15000)")
    ap.add_argument("--max-resolve", type=int, default=2500, help="cap on hostnames resolved in phase 2 (default: 2500)")
    ap.add_argument("--max-ips", type=int, default=150, help="cap on unique IPs enriched in phase 2 (default: 150)")
    ap.add_argument("--proxy", help="http(s) proxy URL for every request, e.g. http://127.0.0.1:8080")
    ap.add_argument("--user-agent", default=UA, help="custom User-Agent header")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress progress output on stderr")
    ap.add_argument("-v", "--verbose", action="store_true", help="print each HTTP request as it happens")
    ap.add_argument("--list-modules", action="store_true", help="list available modules and exit")
    ap.add_argument("--version", action="version", version=__version__)
    return ap


def print_module_list():
    print("Modules (name, phase, modes, description, required key):\n")
    for n, spec in sorted(MODULES.items()):
        keytxt = ("  [needs: %s]" % " or ".join(spec["keys"])) if spec["keys"] else ""
        print("  %-16s phase %d  %-9s %s%s" % (n, spec["phase"], "/".join(sorted(spec["modes"])), spec["desc"], keytxt))


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    if args.list_modules:
        print_module_list()
        return 0
    parser = build_arg_parser()
    if not args.target:
        parser.error("a target is required (domain, URL or IP) unless --list-modules is given")

    log = Logger(quiet=args.quiet, verbose=args.verbose)
    try:
        target = parse_target(args.target, exact=args.exact)
    except ValueError as e:
        log.info("error: %s" % e)
        return 2

    only = [x.strip() for x in args.only.split(",")] if args.only else None
    skip = [x.strip() for x in args.skip.split(",")] if args.skip else None
    args.only, args.skip = only, skip

    keys = load_keys(args.keys_file)
    http = Http(args.timeout, args.proxy, args.user_agent, args.retries, log)
    doh = DoH(http)
    res = Results(target, args.max_urls)
    ctx = Ctx(target, res, http, doh, keys, args, log)

    log.info("[*] target: %s  (kind=%s, scope=%s)" % (target.raw, target.kind, target.scope))
    log.info("[*] passive sources only — this script never contacts the target's own servers directly")
    if keys:
        log.info("[*] API keys loaded: %s" % ", ".join(sorted(keys)))
    t0 = time.monotonic()
    try:
        runnable = run_scan(ctx)
    except SystemExit as e:
        log.info("error: %s" % e)
        return 2
    elapsed = time.monotonic() - t0
    log.info("[*] scan finished in %.1fs — %d hosts, %d IPs, %d URLs, %d findings, %d HTTP request(s)" %
            (elapsed, len(res.hosts), len(res.ips), len(res.urls), len(res.findings), http.requests))

    d = result_to_dict(ctx, runnable, elapsed, args)
    outdir = args.outdir or ("recon_%s_%s" % (re.sub(r"[^a-zA-Z0-9.-]", "_", target.scope), utcnow().strftime("%Y%m%dT%H%M%SZ")))
    os.makedirs(outdir, exist_ok=True)
    formats = {f.strip().lower() for f in args.formats.split(",") if f.strip()}
    written = []
    if "json" in formats:
        path = os.path.join(outdir, "report.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2, default=str)
        written.append(path)
    if "md" in formats:
        path = os.path.join(outdir, "report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(d))
        written.append(path)
    if "html" in formats:
        path = os.path.join(outdir, "report.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(d))
        written.append(path)

    print("\nReports written to %s/:" % outdir)
    for path in written:
        print("  - %s" % path)
    sev_counts = Counter(f["severity"] for f in d["findings"])
    if sev_counts:
        print("\nFindings: " + ", ".join("%d %s" % (sev_counts[sev], sev) for sev in ("high", "medium", "low", "info")
                                         if sev_counts.get(sev)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)




