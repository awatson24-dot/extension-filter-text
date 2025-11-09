import requests
import re #pattern

all_network_types = []
def annotate_modifier(line, force_third_party=False):
    line = line.strip()
    if not line or line.startswith('!'):
        return line

    if '$' in line:
        filter_part, mods = line.split('$', 1)
        if force_third_party and 'third-party' not in mods:
            mods += ',third-party'
        return f"{filter_part}${mods}"

    is_domain_bound = line.startswith('||') or line.startswith('|http')
    modifier, rtype = '', None

    ext_map = {
        'image': ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico'),
        'script': ('.js',),
        'stylesheet': ('.css',),
        'font': ('.woff', '.woff2', '.ttf', '.otf'),
        'media': ('.mp4', '.webm', '.mp3', '.ogg', '.m4a'),
    }

    for key, exts in ext_map.items():
        if line.endswith(exts):
            modifier = key
            break

    if not modifier and ('?' in line or 'track' in line or 'collect' in line):
        modifier = 'xmlhttprequest'

    if force_third_party or not is_domain_bound:
        modifier = f"{modifier},third-party" if modifier else "third-party"

    return f"{line}${modifier}" if modifier else line

def add_missing_modifier(filter_string: str):
    parts = filter_string.split('$')

    if len(parts) == 1:
        return parts[0] + '$third-party,cookie'

    # Split and normalize modifiers
    modifiers = [m.strip() for m in parts[1].split(',')]

    # Add missing ones
    if 'cookie' not in modifiers:
        modifiers.append('cookie')
    if 'third-party' not in modifiers:
        modifiers.append('third-party')

    return parts[0] + '$' + ','.join(modifiers)

def convert_all_document_everything(filter_string: str) -> tuple:
    line = filter_string.split('$')[0]

    # adds document
    document_line = f'{line}$document'

    # adds popups
    popup_line = f'{line}$popup'

    #adds everything else
    regular = f'{line}'

    return document_line, popup_line, regular

def convert_denyallow_filter_to_exceptions(filter_string: str):
    if '$' not in filter_string:
        return []

    placeholder, mods = filter_string.split('$', 1)
    modifiers = mods.split(',')

    allow_list = next((m for m in modifiers if m.startswith('denyallow=')), None)
    domain_mod = next((m for m in modifiers if m.startswith('domain=')), None)
    other_mods = [m for m in modifiers if not m.startswith('denyallow=') and not m.startswith('domain=')]

    allow_set = set()
    block_set = set()
    if allow_list and domain_mod:
        allowed_domains = allow_list[len("denyallow="):].split('|')
        final_mods = ','.join(other_mods + [domain_mod])

        for domain in allowed_domains:
            base = f"@@||{domain}^"
            rule = f"{base}${final_mods}" if final_mods else base
            allow_set.add(rule)

        # Reconstructed base rule (without denyallow)
        base_rule = f"{placeholder}${final_mods}"
        block_set.add(base_rule)

    return allow_set, block_set

def fetch_url(url, json_mode=False):
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        return res.json() if json_mode else res.text
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return {} if json_mode else ""

def further_remove(list1: list, list2: set):
    return {
        line for line in list1
        if line.split('$', 1)[0] not in list2
    }

def get_filter(line):
    parts = line.split('$', 1)

    potential_domain = parts[0]

    url_filter, req_domain = '', []

    if potential_domain.startswith('||'):

        without_prefix = potential_domain[2:]

        if without_prefix.endswith('^'):
            domain_only = without_prefix[:-1]
            url_filter = f"||{domain_only}" if domain_only.endswith('/') else f"||{domain_only}/"

        elif '^*' in without_prefix:
            domain_only, funny_part = without_prefix.split('^*')
            req_domain.append(domain_only)
            url_filter = funny_part

        else:
            domain_only, path = without_prefix.split('/', 1)
            req_domain.append(domain_only)
            url_filter = f"/{path}"

    elif potential_domain.startswith('|'):
        url_filter = potential_domain[1:]

    return url_filter, req_domain, parts[1].split(',') if len(parts) > 1 else []

def remove_redundant_filters(filters) -> tuple:
    popup_patterns = set()
    cleaned_filters = set()

    for rule in filters:
        if '$popup' in rule:
            base = re.sub(r'\$(popup|document).*', '', rule)
            popup_patterns.add(base.strip())


    for rule in filters:
        if '$document' in rule or '$all' in rule:
            base = re.sub(r'\$(popup|document|all).*', '', rule).strip()
            if base in popup_patterns:
                continue  # skip redundant $document
        cleaned_filters.add(rule)

    return separate_filters(cleaned_filters)

def replace_doc_modifier(line):
    if '$' in line:
        before, modifiers = line.split('$', 1)
        # Replace standalone 'doc' safely
        modifiers = re.sub(r'(^|,)\s*doc(?=,|$)', r'\1document', modifiers)

        mods = modifiers.split(',')

        if 'document' in mods and 'popup' in mods:
            mods.remove('document')

        return f"{before}${','.join(mods)}"
    else:
        return line  # no modifiers, return as-is

def separate_filters(filters) -> tuple:
    every_filters = set()
    doc_filters = set()

    for rule in filters:
        if re.search(r"\$.*\bdocument\b", rule):
            doc_filters.add(rule)
        else:
            every_filters.add(rule)

    return every_filters, doc_filters

