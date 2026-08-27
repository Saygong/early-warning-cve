#!/usr/bin/env python3

# SIMPLE OpenCVE scraper.
# Reads vendor/product rows from assets_test.xlsx and writes CVE matches to cves_last_week.csv.

import csv
import json
import re
import os
import requests
import urllib3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote_plus
from openpyxl import load_workbook
from dotenv import load_dotenv

load_dotenv()

# The site we query.
BASE_URL = 'https://app.opencve.io/api/v2'


LOOKBACK_DAYS = int(os.getenv('LOOKBACK_DAYS', '7'))
CVSS_THRESHOLD = float(os.getenv('CVSS_THRESHOLD'))
EPSS_THRESHOLD = float(os.getenv('EPSS_THRESHOLD'))
DIRECT_LINE_BASE_URL = os.getenv('DIRECT_LINE_BASE_URL')
DIRECT_LINE_TIMEOUT = int(os.getenv('DIRECT_LINE_TIMEOUT', '30'))
AGENT_RESPONSE_TIMEOUT = float(os.getenv('DIRECT_LINE_RESPONSE_TIMEOUT', '90'))
POLL_INTERVAL = 1.5

ASSETS_FILE_PATH = os.getenv('PATH_INPUT_FILE', 'assets_test.xlsx')
OUTPUT_CSV_FILE = os.getenv('PATH_OUTPUT_FILE', 'cves_last_week.csv')

# CSV columns we preserve.
CSV_HEADERS = [
    'Vendor Name',
    'Product Name',
    'CVE ID',
    'Created Date',
    'CVSS',
    'EPSS',
    'Description',   
]

ai_integration = os.getenv('USE_COPILOT').strip()
if ai_integration.lower() in ('1', 'true', 'yes'):
    CSV_HEADERS.extend([
        'Business Impact Analysis',
        'Remediation Suggestions',
    ])


# Use a single session for OpenCVE requests.
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (compatible; early-warning-cve/1.0)',
    'Accept': 'application/json, text/plain, */*',
})

_token = os.getenv('OPENCVE_API_TOKEN')
if not _token:
    raise SystemExit('OPENCVE_API_TOKEN environment variable is required')
session.headers.update({'Authorization': f'Bearer {_token}'})

_verify_env = os.getenv('OPENCVE_VERIFY')
VERIFY_SSL = not (_verify_env is None or _verify_env.lower() in ('0', 'false', 'no'))
session.verify = VERIFY_SSL
if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def api_get(url, params=None):
    """GET helper for the OpenCVE API; returns parsed JSON."""
    resp = session.get(url, params=params, timeout=30)
    resp.raise_for_status()
    try:
        return resp.json()
    except ValueError:
        raise ValueError('Invalid JSON response from OpenCVE API')


def slugify(text):
    """Convert a name to the form OpenCVE expects in query strings."""
    if not text:
        return ''

    text = text.strip().lower()
    text = re.sub(r'[^a-z0-9]+', '_', text)
    text = re.sub(r'_+', '_', text)
    return text.strip('_')


def read_assets_from_excel(path):
    """Read vendor and product names from the Excel file."""
    workbook = load_workbook(path)
    worksheet = workbook.active

    # Read the first row as headers.
    header_row = next(worksheet.iter_rows(min_row=1, max_row=1, values_only=True))
    headers = [str(cell).strip().lower() if cell else '' for cell in header_row]

    # Only vendor_name and product_name are required.
    required = ['vendor_name', 'product_name']
    missing = [name for name in required if name not in headers]
    if missing:
        raise ValueError(f'Missing Excel columns: {missing}')

    assets = []
    for row in worksheet.iter_rows(min_row=2):
        if all(cell.value is None for cell in row):
            return assets

        vendor_name = str(row[headers.index('vendor_name')].value).strip()
        product_name = str(row[headers.index('product_name')].value).strip()


        assets.append({
            'vendor_name': vendor_name,
            'product_name': product_name,
        })

    return assets


def parse_date(text):
    """Try to parse a date string from the OpenCVE results."""
    if not text:
        return None

    text = text.strip()
    if not text or text.lower() in {'n/a', 'unknown', '-'}:
        return None

    for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%d/%m/%Y', '%m/%d/%Y', '%d-%b-%Y', '%b %d, %Y', '%d %b %Y'):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        return None


def parse_score(value):
    """Extract a numeric score from a scalar or nested API value."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        match = re.search(r'\d+(?:\.\d+)?', value)
        return float(match.group()) if match else None
    if isinstance(value, dict):
        for key in ('score', 'base_score', 'value'):
            if key in value:
                score = parse_score(value[key])
                if score is not None:
                    return score
        for nested_value in value.values():
            score = parse_score(nested_value)
            if score is not None:
                return score
    return None


def find_field(data, names):
    """Find the first matching field recursively in an API response."""
    if isinstance(data, dict):
        for name in names:
            if name in data and data[name] is not None:
                return data[name]
        for value in data.values():
            found = find_field(value, names)
            if found is not None:
                return found
    elif isinstance(data, list):
        for value in data:
            found = find_field(value, names)
            if found is not None:
                return found
    return None


def fetch_cves_from_api(vendor_slug, product_slug):
    """Fetch CVEs for a vendor/product via OpenCVE API (handles simple pagination).

    Returns a list of JSON CVE items (structure may vary slightly across API versions),
    so callers should access fields defensively.
    """
    url = f'{BASE_URL}/vendors/{quote_plus(vendor_slug)}/products/{quote_plus(product_slug)}/cves'
    items = []
    page = 1
    per_page = 100
    while True:
        params = {'page': page, 'per_page': per_page}
        data = api_get(url, params=params)

        # Support several common pagination/response shapes
        page_items = []
        if isinstance(data, dict):
            if 'items' in data:
                page_items = data['items']
                has_next = bool(data.get('next'))
            elif 'data' in data:
                page_items = data['data']
                has_next = bool(data.get('next'))
            elif 'results' in data:
                page_items = data['results']
                has_next = bool(data.get('next')) or bool(data.get('next_page'))
            else:
                # Some endpoints return a paginated object with 'items' under another key
                # or a single list under a named key. Try to heuristically pick the first list.
                for v in data.values():
                    if isinstance(v, list):
                        page_items = v
                        break
                has_next = False
        elif isinstance(data, list):
            page_items = data
            has_next = False
        else:
            raise ValueError('Unexpected response shape from OpenCVE API')

        items.extend(page_items)
        if not has_next or len(page_items) < per_page:
            break
        page += 1

    return items


def fetch_cve_detail(cve_id):
    """Fetch the full CVE record, including CVSS and EPSS scores."""
    url = f'{BASE_URL}/cves/{quote_plus(cve_id)}'
    return api_get(url)


def filter_recent(rows):
    """Keep only rows updated within the last LOOKBACK_DAYS."""
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=LOOKBACK_DAYS)
    def updated_date(r):
        ud = r.get('created_at')
        if not ud:
            return None
        return parse_date(str(ud))

    return [row for row in rows if updated_date(row) and updated_date(row) >= cutoff]


def filter_critical(rows):
    """Keep rows with CVSS >= 8.0 OR EPSS >= 0.1."""
    return [
        row for row in rows
        if (row.get('cvss') is not None and row['cvss'] >= CVSS_THRESHOLD)
        or (row.get('epss') is not None and row['epss'] >= EPSS_THRESHOLD)
    ]


def write_csv(filename, rows):
    """Write output rows to a CSV file."""
    with open(filename, 'w', newline='', encoding='utf-8') as out_file:
        writer = csv.writer(out_file)
        writer.writerow(CSV_HEADERS)
        writer.writerows(rows)


def directline_request(method, url, token, **kwargs):
    """Execute a Direct Line request and return its JSON response."""
    headers = kwargs.pop('headers', {})
    headers['Authorization'] = f'Bearer {token}'
    response = requests.request(
        method,
        url,
        verify=VERIFY_SSL,
        headers=headers,
        timeout=DIRECT_LINE_TIMEOUT,
        **kwargs,
    )
    response.raise_for_status()
    return response.json() if response.content else {}


def business_impact_analysis_copilot(vulnerability):
    """Send one vulnerability to Copilot Studio and return its business impact analysis."""
    secret = os.getenv('COPILOT_AGENT_SECRET').strip()
    if not secret:
        raise RuntimeError('COPILOT_AGENT_SECRET environment variable is required')

    token_data = directline_request(
        'POST',
        f'{DIRECT_LINE_BASE_URL}/tokens/generate',
        secret,
        headers={'Content-Type': 'application/json'},
    )
    token = token_data.get('token')
    if not token:
        raise RuntimeError('Direct Line token missing from response')

    conversation_data = directline_request(
        'POST',
        f'{DIRECT_LINE_BASE_URL}/conversations',
        token,
    )
    conversation_id = conversation_data.get('conversationId')
    if not conversation_id:
        raise RuntimeError('Direct Line conversationId missing from response')

    prompt = (
        'Analizza la seguente vulnerabilita e produci un testo in linguaggio business '
        'di massimo 70 parole in cui descrivi i potenziali impatti, se esiste un '
        'exploit pubblico e cosa succede se non viene patchata. Se un dato manca nel '
        'JSON, dichiaralo chiaramente.\n\nJSON:\n'
        + json.dumps(vulnerability, ensure_ascii=False, separators=(',', ':'))
    )
    activity_data = directline_request(
        'POST',
        f'{DIRECT_LINE_BASE_URL}/conversations/{conversation_id}/activities',
        token,
        headers={'Content-Type': 'application/json'},
        json={
            'type': 'message',
            'locale': 'it-IT',
            'from': {'id': 'script', 'role': 'user'},
            'text': prompt,
        },
    )
    sent_activity_id = activity_data.get('id')
    if not sent_activity_id:
        raise RuntimeError('Direct Line activity id missing from response')

    deadline = time.monotonic() + AGENT_RESPONSE_TIMEOUT
    watermark = None
    while time.monotonic() < deadline:
        params = {'watermark': watermark} if watermark else None
        activities_data = directline_request(
            'GET',
            f'{DIRECT_LINE_BASE_URL}/conversations/{conversation_id}/activities',
            token,
            params=params,
        )
        watermark = activities_data.get('watermark')
        for activity in activities_data.get('activities', []):
            if activity.get('id') == sent_activity_id:
                continue
            sender = activity.get('from') or {}
            if activity.get('type') == 'message' and activity.get('text') and sender.get('id') != 'script':
                return activity['text'].strip()
        time.sleep(POLL_INTERVAL)

    raise TimeoutError(f'No Copilot response within {AGENT_RESPONSE_TIMEOUT} seconds')

def remediation_suggestions_copilot(vulnerability):
    """Send one vulnerability to Copilot Studio and return its remediation suggestions."""
    secret = os.getenv('COPILOT_AGENT_SECRET').strip()
    if not secret:
        raise RuntimeError('COPILOT_AGENT_SECRET environment variable is required')

    token_data = directline_request(
        'POST',
        f'{DIRECT_LINE_BASE_URL}/tokens/generate',
        secret,
        headers={'Content-Type': 'application/json'},
    )
    token = token_data.get('token')
    if not token:
        raise RuntimeError('Direct Line token missing from response')

    conversation_data = directline_request(
        'POST',
        f'{DIRECT_LINE_BASE_URL}/conversations',
        token,
    )
    conversation_id = conversation_data.get('conversationId')
    if not conversation_id:
        raise RuntimeError('Direct Line conversationId missing from response')

    prompt = (
        'Analizza la seguente vulnerabilita e produci un testo in linguaggio business '
        'di massimo 50 parole in cui descrivi e consigli le attività di remediation o, se non possibile, le misure mitigazione.\n\nJSON:\n'
        + json.dumps(vulnerability, ensure_ascii=False, separators=(',', ':'))
    )
    activity_data = directline_request(
        'POST',
        f'{DIRECT_LINE_BASE_URL}/conversations/{conversation_id}/activities',
        token,
        headers={'Content-Type': 'application/json'},
        json={
            'type': 'message',
            'locale': 'it-IT',
            'from': {'id': 'script', 'role': 'user'},
            'text': prompt,
        },
    )
    sent_activity_id = activity_data.get('id')
    if not sent_activity_id:
        raise RuntimeError('Direct Line activity id missing from response')

    deadline = time.monotonic() + AGENT_RESPONSE_TIMEOUT
    watermark = None
    while time.monotonic() < deadline:
        params = {'watermark': watermark} if watermark else None
        activities_data = directline_request(
            'GET',
            f'{DIRECT_LINE_BASE_URL}/conversations/{conversation_id}/activities',
            token,
            params=params,
        )
        watermark = activities_data.get('watermark')
        for activity in activities_data.get('activities', []):
            if activity.get('id') == sent_activity_id:
                continue
            sender = activity.get('from') or {}
            if activity.get('type') == 'message' and activity.get('text') and sender.get('id') != 'script':
                return activity['text'].strip()
        time.sleep(POLL_INTERVAL)

    raise TimeoutError(f'No Copilot response within {AGENT_RESPONSE_TIMEOUT} seconds')

def extract_cve_fields(item):
    """Normalize a CVE item from the API into our expected dict keys."""
    def get_first(keys, default=''):
        for k in keys:
            if k in item and item[k] is not None:
                return item[k]
        return default

    cve_id = get_first(['id', 'cve_id', 'cve', 'name'])
    created_at = get_first(['created_at', 'published_at', 'published'])
    description = get_first(['description', 'summary'])
    cvss_value = find_field(item, ('cvss_v3_1', 'cvss31', 'cvss_score', 'cvss_v3', 'v3_1', 'cvss'))
    epss_value = find_field(item, ('epss', 'epss_score'))

    # Normalize vendors/products to strings
    def list_to_str(v):
        if not v:
            return ''
        if isinstance(v, list):
            return ' '.join(str(x) for x in v)
        return str(v)

    return {
        'cve_id': str(cve_id),
        'created_at': str(created_at),
        'cvss': parse_score(cvss_value),
        'epss': parse_score(epss_value),
        'description': str(description),
    }


def get_cves_for_asset(asset):
    """Fetch and return CVE rows for a single asset using the OpenCVE API."""
    vendor_name = asset['vendor_name']
    product_name = asset['product_name']
    vendor_slug = slugify(vendor_name)
    product_slug = slugify(product_name)

    print(f'[*] Querying OpenCVE API: vendor={vendor_name}, product={product_name}')
    items = fetch_cves_from_api(vendor_slug, product_slug)

    # The list endpoint has publication dates; fetch details only for recent CVEs.
    rows_with_json = []
    for item in items:
        row = extract_cve_fields(item)
        row['_raw_json'] = item
        rows_with_json.append(row)

    rows = filter_recent(rows_with_json)
    detailed_rows = []
    for row in rows:
        detail = fetch_cve_detail(row['cve_id'])
        vulnerability_json = {**row['_raw_json'], **detail}
        detailed_row = extract_cve_fields(vulnerability_json)
        detailed_row['_raw_json'] = vulnerability_json
        detailed_rows.append(detailed_row)

    #rows = filter_critical(detailed_rows)

    directline_secret = os.getenv('COPILOT_AGENT_SECRET').strip()
    if not directline_secret:
        raise SystemExit('COPILOT_AGENT_SECRET environment variable is required')

    output = []
    for row in rows:
        ai_integration = os.getenv('USE_COPILOT').strip()
        
        output.append([
            vendor_name,
            product_name,
            row.get('cve_id', ''),
            row.get('created_at', ''),
            '' if row.get('cvss') is None else str(row['cvss']),
            '' if row.get('epss') is None else str(row['epss']),
            row.get('description', ''),
        ])

        if ai_integration.lower() in ('1', 'true', 'yes'):
            business_analysis = business_impact_analysis_copilot(row['_raw_json'])
            remediation_analysis = remediation_suggestions_copilot(row['_raw_json'])
            output[-1].append(business_analysis)
            output[-1].append(remediation_analysis)

    print(f'[*] Found {len(output)} CVEs for {vendor_name} / {product_name}')
    return output


def main():
    """Main script flow: read assets, query OpenCVE, and save CSV."""
    assets_path = Path(ASSETS_FILE_PATH)
    if not assets_path.exists():
        raise SystemExit(f'Excel file not found: {assets_path}')

    # Return a list of dicts with 'vendor_name' and 'product_name' keys. 
    assets = read_assets_from_excel(assets_path)
    if not assets:
        raise SystemExit('No valid vendor/product rows found in the Excel file')

    all_rows = []
    for asset in assets:
        try:
            all_rows.extend(get_cves_for_asset(asset))
        except Exception as exc:
            print(f'[!] Skipping {asset["vendor_name"]} / {asset["product_name"]}: {exc}')

    write_csv(OUTPUT_CSV_FILE, all_rows)
    print(f'[*] Saved {len(all_rows)} rows to {OUTPUT_CSV_FILE}')


if __name__ == '__main__':
    main()
