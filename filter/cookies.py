import requests
import re

import requests

def cookies_rules(url):
    results = {
        "third_party_cookies": set(),
        "dynamic_cookies": set(),
        "specific_block": set()
    }

    section_ranges = {
        ("! easylist_cookie_thirdparty.txt", "! easylist_cookie_specific_block.txt"): "third_party_cookies",
        ("! easylist_cookie_general_block.txt", "! easylist_cookie_general_hide.txt"): "dynamic_cookies",
        ("! easylist_cookie_specific_block.txt", "! easylist_cookie_specific_hide.txt") : "specific_block"
    }

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Unable to fetch list {url} : {e}")
        return

    current_key = None
    end_marker = None

    for line in response.text.splitlines():

        # Check for start of a section
        for (start, end), key in section_ranges.items():
            if line == start:
                current_key = key
                end_marker = end
                break

        if line == end_marker and current_key:
            current_key = None
            end_marker = None
            continue

        if current_key and not line.startswith('!') and line.strip():
            results[current_key].add(line)

    return {key: sorted(values) for key, values in results.items()}

def cookie_static(dictionary: dict) -> list:
    static_cookies = []

    for index, cookie in enumerate(dictionary.get('third_party_cookies')):
        portions = cookie.split('$')
        important = portions[0]

        modifiers = portions[1].split(',') if len(portions) > 1 else []


        if important.endswith('^'):
            url_filter = important[:-1] + "/"
        elif '^*' in important:
            url_filter = important.replace('^*', '/')
        else :
            url_filter = important

        url_filter = re.sub(r'/+', '/', url_filter)

        rule = {
            "id" : index + 1,
            "priority" : 3,
            "action" : {
                "type": "modifyHeaders",
                "requestHeaders": [{"header": "cookie", "operation": "remove"}],
                "responseHeaders": [{"header": "set-cookie", "operation": "remove"}]
            },
            "condition": {
                "urlFilter" : url_filter,
                "domainType" : "thirdParty",
                "resourceTypes" : ["sub_frame"]
            }
        }

        for mod in modifiers:
            if mod == 'script':
                rule['condition']['resourceTypes'].append('script')

            if 'domain=' in mod:
                get_domains = mod[7:].split('|')

                for d in get_domains:
                    target_list = "excludedInitiatorDomains" if d.startswith('~') else "initiatorDomains"
                    rule['condition'].setdefault(target_list, []).append(d.lstrip('~'))

        static_cookies.append(rule)

    return static_cookies