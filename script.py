#!/usr/bin/env python3

# SIMPLE OpenCVE scraper.
# Reads vendor/product rows from assets_test.xlsx and writes CVE matches to cves_last_week.csv.

import csv
import re
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup
from openpyxl import load_workbook

# The site we query.
BASE_URL = 'https://app.opencve.io'

# Only rows updated in the last X days are kept.
LOOKBACK_DAYS = 7

# Input and output files are hardcoded for simplicity.
ASSETS_FILE_PATH = os.getenv('ASSET_PATH')
OUTPUT_CSV_FILE = 'cves_last_week.csv'

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

# Use a single session for all requests.
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
})


def fetch_html(url):
    """Fetch HTML from the given URL using requests."""
    response = session.get(url, timeout=30)
    response.raise_for_status()
    return response.text


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

        def value(column_name):
            return row[headers.index(column_name)].value if column_name in headers else None

        vendor_name = str(value('vendor_name') or '').strip()
        product_name = str(value('product_name') or '').strip()

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


def parse_cve_rows(html):
    """Extract CVE rows from the OpenCVE HTML table."""
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table')
    if table is None:
        raise ValueError('No CVE table found on OpenCVE page')

    rows = []
    current = None

    for tr in table.find_all('tr'):
        # Skip header rows.
        if tr.find('th'):
            continue

        cells = tr.find_all('td')
        if not cells:
            continue

        # Some rows are just the description row.
        if len(cells) == 1 and current is not None:
            current['description'] = cells[0].get_text(' ', strip=True)
            continue

        # Only process rows with at least the expected 5 columns.
        if len(cells) < 5:
            continue

        current = {
            'cve_id': cells[0].get_text(strip=True),
            'vendors': cells[1].get_text(' ', strip=True),
            'products': cells[2].get_text(' ', strip=True),
            'updated': cells[3].get_text(strip=True),
            'cvss': cells[4].get_text(' ', strip=True),
            'description': '',
        }
        rows.append(current)

    return rows


def filter_recent(rows):
    """Keep only rows updated within the last LOOKBACK_DAYS."""
    cutoff = datetime.utcnow().date() - timedelta(days=LOOKBACK_DAYS)
    return [row for row in rows if parse_date(row['updated']) and parse_date(row['updated']) >= cutoff]

def filter_critical(rows):
    """Keep only rows with CVSS score >= 8.0."""

    return [row for row in rows if float(row['cvss'].split()[0]) >= 8.0]


def write_csv(filename, rows):
    """Write output rows to a CSV file."""
    with open(filename, 'w', newline='', encoding='utf-8') as out_file:
        writer = csv.writer(out_file)
        writer.writerow(CSV_HEADERS)
        writer.writerows(rows)


def get_cves_for_asset(asset):
    """Fetch and return CVE rows for a single asset."""
    vendor_name = asset['vendor_name']
    product_name = asset['product_name']
    url = build_search_url(vendor_name, product_name)

    print(f'[*] Querying OpenCVE: vendor={vendor_name}, product={product_name}')
    html = fetch_html(url)
    rows = parse_cve_rows(html)
    rows = filter_recent(rows)
    rows = filter_critical(rows)

    output = []
    for row in rows:
        output.append([
            vendor_name,
            product_name,
            url,
            row['cve_id'],
            row['vendors'],
            row['products'],
            row['updated'],
            row['cvss'],
            row['description'],
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
