#!/usr/bin/env python3

# SIMPLE OpenCVE scraper.
# Reads vendor/product rows from assets_test.xlsx and writes CVE matches to cves_last_week.csv.

import csv
import re
import os
import time
import requests
import urllib3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote_plus
from openpyxl import load_workbook
from dotenv import load_dotenv

load_dotenv()

# The site we query.
BASE_URL = 'https://app.opencve.io/api/v2'


# Only rows updated in the last X days are kept.
LOOKBACK_DAYS = int(os.getenv('LOOKBACK_DAYS', '7'))
CVSS_THRESHOLD = 8.0
EPSS_THRESHOLD = 0.1

# Input and output files are hardcoded for simplicity.
ASSETS_FILE_PATH = os.getenv('PATH_INPUT_FILE')
OUTPUT_CSV_FILE = os.getenv('PATH_OUTPUT_FILE')

# CSV columns we preserve.
CSV_HEADERS = [
    'Vendor Name',
    'Product Name',
    'Query URL',
    'CVE ID',
    'Vendors',
    'Products',
    'Updated Date',
    'CVSS',
    'Description',
]

# Use a single session for all requests. Session granted by an API token set via environment variable.
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (compatible; early-warning-cve/1.0)',
    'Accept': 'application/json, text/plain, */*',
})

# Authorization: only set if token present
_token = os.getenv('OPENCVE_API_TOKEN')
time.sleep(2)
if not _token:
    raise SystemExit('OPENCVE_API_TOKEN environment variable is required')
session.headers.update({'Authorization': f'Bearer {_token}'})

# SSL verification behaviour: allow custom CA bundle or disable verification for
# environments with MITM/self-signed certificates. Prefer setting OPENCVE_CACERT
# to a CA bundle path; set OPENCVE_VERIFY to 'false' to disable verification.
_cacert = os.getenv('OPENCVE_CACERT')
_verify_env = os.getenv('OPENCVE_VERIFY')
# Default to disabling verification per user request; allow enabling via OPENCVE_VERIFY
if _cacert:
    session.verify = _cacert
else:
    if _verify_env is None:
        session.verify = False
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    elif _verify_env.lower() in ('0', 'false', 'no'):
        session.verify = False
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    else:
        session.verify = True



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
            continue

        vendor_name = str(row[headers.index('vendor_name')].value).strip()
        product_name = str(row[headers.index('product_name')].value).strip()

        # Skip rows that are incomplete.
        if not vendor_name or not product_name:
            continue

        assets.append({
            'vendor_name': vendor_name,
            'product_name': product_name,
        })

    return assets


def build_search_url(vendor_name, product_name):
    """Build the OpenCVE search URL for a vendor/product pair."""
    vendor_slug = slugify(vendor_name)
    product_slug = slugify(product_name)
    return f'{BASE_URL}/cve/?vendor={quote_plus(vendor_slug)}&product={quote_plus(product_slug)}'


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


def filter_recent(rows):
    """Keep only rows updated within the last LOOKBACK_DAYS."""
    cutoff = datetime.utcnow().date() - timedelta(days=LOOKBACK_DAYS)
    def updated_date(r):
        ud = r.get('updated') or r.get('modified') or r.get('last_modified')
        if not ud:
            return None
        return parse_date(str(ud))

    return [row for row in rows if updated_date(row) and updated_date(row) >= cutoff]

def filter_critical(rows):
    """Keep only rows with CVSS score >= 8.0. Works with numeric or nested cvss score."""
    def score_of(r):
        cvss = r.get('cvss') or r.get('cvss_score') or r.get('metrics')
        # numeric
        try:
            if isinstance(cvss, (int, float)):
                return float(cvss)
            if isinstance(cvss, str):
                return float(cvss.split()[0])
            if isinstance(cvss, dict):
                for k in ('score', 'base_score', 'cvss'):
                    if k in cvss:
                        return float(cvss[k])
        except Exception:
            return 0.0
        return 0.0

    return [row for row in rows if score_of(row) >= 8.0]


def write_csv(filename, rows):
    """Write output rows to a CSV file."""
    with open(filename, 'w', newline='', encoding='utf-8') as out_file:
        writer = csv.writer(out_file)
        writer.writerow(CSV_HEADERS)
        writer.writerows(rows)


def extract_cve_fields(item):
    """Normalize a CVE item from the API into our expected dict keys."""
    def get_first(keys, default=''):
        for k in keys:
            if k in item and item[k] is not None:
                return item[k]
        return default

    cve_id = get_first(['id', 'cve_id', 'cve', 'name'])
    vendors = get_first(['vendors', 'vendor', 'vendors_list'])
    products = get_first(['products', 'product', 'products_list'])
    updated = get_first(['updated', 'modified', 'last_modified', 'updated_at'])
    description = get_first(['summary', 'description'])
    cvss = get_first(['cvss', 'cvss_score', 'score', 'base_score', 'metrics'])

    # Normalize vendors/products to strings
    def list_to_str(v):
        if not v:
            return ''
        if isinstance(v, list):
            return ' '.join(str(x) for x in v)
        return str(v)

    return {
        'cve_id': str(cve_id),
        'vendors': list_to_str(vendors),
        'products': list_to_str(products),
        'updated': str(updated),
        'cvss': cvss,
        'description': str(description),
    }


def get_cves_for_asset(asset):
    """Fetch and return CVE rows for a single asset using the OpenCVE API."""
    vendor_name = asset['vendor_name']
    product_name = asset['product_name']
    vendor_slug = slugify(vendor_name)
    product_slug = slugify(product_name)

    print(f'[*] Querying OpenCVE API: vendor={vendor_name}, product={product_name}')
    try:
        items = fetch_cves_from_api(vendor_slug, product_slug)
    except Exception as exc:
        raise

    # Normalize items into rows
    rows = [extract_cve_fields(i) for i in items]
    rows = filter_recent(rows)
    rows = filter_critical(rows)

    output = []
    query_url = build_search_url(vendor_name, product_name)
    for row in rows:
        output.append([
            vendor_name,
            product_name,
            query_url,
            row.get('cve_id', ''),
            row.get('vendors', ''),
            row.get('products', ''),
            row.get('updated', ''),
            str(row.get('cvss', '')),
            row.get('description', ''),
        ])

    print(f'[*] Found {len(output)} CVEs for {vendor_name} / {product_name}')
    return output


def main():
    """Main script flow: read assets, scrape OpenCVE, and save CSV."""
    assets_path = Path(ASSETS_FILE_PATH)
    if not assets_path.exists():
        raise SystemExit(f'Excel file not found: {assets_path}')

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
