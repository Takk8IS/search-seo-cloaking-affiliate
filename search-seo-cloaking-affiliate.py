import builtwith
import dns.resolver
import json
import nmap
import os
import re
import requests
import shodan
import socket
import tldextract
import whois
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from googlesearch import search
from ipwhois import IPWhois
from rich.console import Console
from rich.table import Table
from urllib.parse import urlparse
from rich.style import Style
from rich.box import ROUNDED

load_dotenv()

# Console Rich to display data
console = Console()

# URL of the page to be analyzed
url = os.getenv("URL")

# Request the page content
try:
    response = requests.get(str(url))
    response.raise_for_status()
    soup = BeautifulSoup(response.content, "html.parser")
except requests.exceptions.RequestException as e:
    console.print(f"Error fetching the URL: {e}")
    exit()

# Common table style
def create_table(title):
    table = Table(title=title, title_style=Style(color="cyan", bold=True), box=ROUNDED)
    table.row_styles = ["none", Style(bgcolor="grey23")]
    return table

# Function to display backlinks in a table
def display_backlinks(backlinks):
    table = create_table("Backlinks Found")
    table.add_column("Backlink", justify="left", no_wrap=False)
    for backlink in backlinks:
        table.add_row(backlink)
    console.print(table)

# Function to display scripts in a table
def display_scripts(scripts):
    table = create_table("Scripts Found")
    table.add_column("Type", justify="left", no_wrap=False)
    table.add_column("Content", justify="left", no_wrap=False)
    for script in scripts:
        if script.string:
            table.add_row("Internal", script.string[:50] + "...")
        elif script.get('src'):
            table.add_row("External", script.get('src'))
    console.print(table)

# Function to display meta tags in a table
def display_meta_tags(meta_tags):
    table = create_table("Meta Tags Found")
    table.add_column("Type", justify="left", no_wrap=False)
    table.add_column("Content", justify="left", no_wrap=False)
    for meta in meta_tags:
        table.add_row(meta.get('http-equiv', 'N/A'), meta.get('content', 'N/A'))
    console.print(table)

# Function to display obfuscated URLs found in scripts
def display_obfuscated_urls(obfuscated_urls):
    table = create_table("Obfuscated URLs Found in Scripts")
    table.add_column("URL", justify="left", no_wrap=False)
    for url in obfuscated_urls:
        table.add_row(url)
    console.print(table)

# Function to display the origin of the ad
def display_ad_origin(aff_id):
    table = create_table("Origin of the Ad")
    table.add_column("Affiliate ID", justify="left", no_wrap=False)
    table.add_row(aff_id)
    console.print(table)

# Function to investigate domain details
def investigate_domain(domain):
    table = create_table(f"Domain Information {domain}")
    table.add_column("Property", justify="left", no_wrap=False)
    table.add_column("Value", justify="left", no_wrap=False)

    # Whois information
    try:
        domain_info = whois.whois(domain)
        table.add_row("Registrant Name", domain_info.name or "N/A")
        table.add_row("Organization", domain_info.org or "N/A")
        table.add_row("Country", domain_info.country or "N/A")
    except Exception as e:
        console.print(f"Error fetching WHOIS data: {e}")

    # DNS Resolution
    try:
        dns_info = dns.resolver.resolve(domain, 'A')
        for ipval in dns_info:
            table.add_row("IP Address", ipval.to_text())
    except Exception as e:
        table.add_row("IP Address", "N/A")

    console.print(table)

# Function to display builtwith information
def display_builtwith_info(url):
    builtwith_info = builtwith.parse(url)
    table = create_table("Technologies Used on the Site")
    table.add_column("Technology", justify="left", no_wrap=False)
    table.add_column("Details", justify="left", no_wrap=False)
    for tech, details in builtwith_info.items():
        table.add_row(tech, ", ".join(details))
    console.print(table)

# Function to perform a Google search and find additional backlinks
def google_search_backlinks(query):
    table = create_table("Backlinks Found by Google")
    table.add_column("Backlink", justify="left", no_wrap=False)
    for result in search(query, num=10):
        table.add_row(result)
    console.print(table)

# Function to search for exposed devices on Shodan
def search_shodan(domain):
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.search(domain)
        table = create_table("Devices Found on Shodan")
        table.add_column("IP", justify="left", no_wrap=False)
        table.add_column("Data", justify="left", no_wrap=False)
        for result in results['matches']:
            table.add_row(result['ip_str'], result['timestamp'])
        console.print(table)
    except shodan.APIError as e:
        console.print(f"Error searching on Shodan: {e}. Please check your API key and account status.")

# Function to get detailed IP information
def get_ip_info(ip):
    obj = IPWhois(ip)
    res = obj.lookup_rdap()
    return res

# Function to display detailed IP information
def display_ip_info(ip):
    info = get_ip_info(ip)
    table = create_table(f"IP Information {ip}")
    table.add_column("Property", justify="left", no_wrap=False)
    table.add_column("Value", justify="left", no_wrap=False)
    for key, value in info.items():
        table.add_row(key, str(value))
    console.print(table)

# Function to perform a port scan
def port_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '22-443')
    table = create_table(f"Port Scan for {ip}")
    table.add_column("Port", justify="left", no_wrap=False)
    table.add_column("State", justify="left", no_wrap=False)
    try:
        for port in nm[ip]['tcp']:
            table.add_row(str(port), nm[ip]['tcp'][port]['state'])
    except KeyError:
        table.add_row("Error", "No TCP information available")
    console.print(table)

# Function to get traffic data using SimilarWeb API
def get_traffic_data(domain):
    api_key = os.getenv("SIMILARWEB_API_KEY")
    url = f"https://api.similarweb.com/v1/website/{domain}/total-traffic-and-engagement/visits?api_key={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        console.print(f"Error fetching traffic data: {e}")
        return None

# Function to display traffic data
def display_traffic_data(data):
    if data:
        table = create_table("Traffic Data")
        table.add_column("Metric", justify="left", no_wrap=False)
        table.add_column("Value", justify="left", no_wrap=False)
        for key, value in data.items():
            table.add_row(key, str(value))
        console.print(table)
    else:
        console.print("Unable to obtain traffic data.")

# Find all links on the page
links = soup.find_all('a', href=True)
backlinks = [link['href'] for link in links if 'http' in link['href'] and 'thedenticore.com' not in link['href']]
display_backlinks(backlinks)

# Check scripts on the page
scripts = soup.find_all('script')
display_scripts(scripts)

# Check meta tags and other possible redirects
meta_tags = soup.find_all('meta')
meta_refresh = [meta for meta in meta_tags if meta.get('http-equiv') == 'refresh']
display_meta_tags(meta_refresh)

# Check for obfuscated URLs
obfuscated_urls = []
for script in scripts:
    if script.string:
        matches = re.findall(r'http[s]?://[^\s"\']+', script.string)
        obfuscated_urls.extend(matches)
display_obfuscated_urls(obfuscated_urls)

# Try to infer the origin of the ad
if 'aff_id' in str(url):
    match = re.search(r'aff_id=(\d+)', str(url))
    if match:
        aff_id = match.group(1)
        display_ad_origin(aff_id)
    else:
        console.print("Unable to extract affiliate ID from URL.")

# Investigate the domain
domain = urlparse(url).netloc
investigate_domain(domain)
display_builtwith_info(url)

# Perform a Google search for additional backlinks
google_search_backlinks("site:" + str(domain))

# Search for exposed devices on Shodan
search_shodan(domain)

# Perform a port scan and display detailed IP information
for ip in ['172.67.199.147', '104.21.44.120']:
    display_ip_info(ip)
    port_scan(ip)

# Get and display traffic data
traffic_data = get_traffic_data(domain)
display_traffic_data(traffic_data)

# Note about visits
console.print("\n[bold red]The number of visits cannot be directly obtained without access to specific site analytics data, but we use SimilarWeb for estimates.[/bold red]")
