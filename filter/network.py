import requests
import re #pattern
from urllib.parse import urlparse
from .utils import annotate_modifier, fetch_url, replace_doc_modifier, convert_denyallow_filter_to_exceptions, \
    remove_redundant_filters, get_filter, convert_all_document_everything


def network_dynamic(lists : list, patterns : list, json_dict : dict, domains : set, max_prev: float = 0.1 ,min_prev: float = 0.01) -> dict :

    third_party, customs, misc, straight_domains, scripts = set(), set(), set(), set(), set()

    results = {
        "adult_third_party" : set(),
        "general_newsletter" : set(),
        "specific_newsletter" : set(),
        "adult_specific" : set(),
        "general_social_block" : set(),
        "easyprivacy_specific" : set(),
        "easyprivacy_general": set(),
        "anti-adblock_general": set()
    }

    section_ranges = {
        ("! *** easylist:easylist_adult/adult_thirdparty.txt ***", "! *** easylist:easylist_adult/adult_thirdparty_popup.txt ***") : "adult_third_party",
        ("! fanboy_newsletter_general_block.txt", "! fanboy_newsletter_international_block.txt") : "general_newsletter",
        ("! fanboy_newsletter_specific_block.txt", "! fanboy_newsletter_general_hide.txt") : "specific_newsletter",
        ("! *** easylist:easylist_adult/adult_specific_block.txt ***", "! *** easylist:easylist_adult/adult_specific_block_popup.txt ***") : "adult_specific",
        ("! fanboy_social_general_block.txt", "! fanboy_social_general_hide.txt") : "general_social_block",
        ("! *** easylist:easyprivacy/easyprivacy_specific.txt ***", "! *** easylist:easyprivacy/easyprivacy_specific_abp.txt ***") : "easyprivacy_specific",
        ("! *** easylist:easylist_adult/adult_allowlist_popup.txt ***", "! *** easylist:easyprivacy/easyprivacy_general_emailtrackers.txt ***"): "easyprivacy_general"
    }

    allow, doc, contains_image, contains_all, csp, remove_param = set(), set(), set(), set(), set(), set()

    domain_line, doc_domains, check = [], [], []

    for url in lists :

        content = fetch_url(url)
        if not content:
            continue

        current_key, end_marker = None, None
        for line in content.splitlines():

            line = replace_doc_modifier(line)
            line = line.strip().replace('%D1%85', '%78')

            for (start, end), key in section_ranges.items():
                if line == start:
                    current_key, end_marker= key, end
                elif line == end_marker and current_key:
                    current_key, end_marker = None, None
                    continue

            if current_key and not line.startswith(('/^', '!', '$')) and '@@' not in line and 'csp' not in line and '##' not in line:
                results[current_key].add(line)
                continue

            # Not needed for right now
            if (
                    "@@" in line or line.startswith(('!', '##', '/\\', '$', '/:', '/(', '/^', '/[', '<a', '<meta')) or
                    '##' in line or 'badfilter' in line or '/[' in line or 'replace' in line or 'redirect=' in line or
                    'inline-script' in line or '$$' in line or '$/$' in line or 'redirect-rule=' in line or
                    'permissions=' in line or 'ipaddress=' in line or 'method=' in line
            ):
                continue

            if re.search(r"\$.*\b(third-party|xmlhttprequest|3p|xhr)\b", line):
                if 'denyallow' in line:
                    temp1, temp2 = convert_denyallow_filter_to_exceptions(line)
                    allow.update(temp1)
                    third_party.update(temp2)
                else:
                    third_party.add(line)

            elif re.search(r"\$.*\ball\b", line):
                d_line, p_line, r_line = convert_all_document_everything(line)

                match = re.search(r"\|\|([^\^]+)\^", line)

                if match:
                    domains.add(r_line)

                else:
                    misc.add(d_line)
                    contains_all.add(r_line)
                    check.append(d_line)

            elif re.search(r"\$.*\b(popup|subdocument|font|document|media|websocket|object|other|ping|stylesheet)\b", line) :
                misc.add(line)

            elif re.search(r"\$.*\bimage\b", line) and url == lists[1]:
                contains_image.add(line)

            elif any(pattern.search(line) for pattern in patterns):
                customs.add(line)

            elif re.search(r"\$.*\bcsp\b", line):
                csp.add(line)

            elif re.search(r"\$.*\bremoveparam\b", line):
                remove_param.add(line)

            elif re.search(r"\$.*\bscript\b", line):
                scripts.add(line)

            elif line.startswith('||') and line.endswith('^') :
                domain = line[2:-1]
                domain_line.append((domain, line))


    # removes duplicates in document seen in popups
    misc, doc = remove_redundant_filters(misc)

    b = list(set([tuple(sorted(t)) for t in domain_line]))

    # Gets tracker radar for domain prevalence
    tracker_data = fetch_url(json_dict.get('duckduckgo'), json_mode= True)

    for domain, line in b:
        if domain in tracker_data:
            prevalence = tracker_data[domain].get('prevalence')

            if prevalence >= min_prev:
                domains.add(line)

    # gets allow filters
    for url in [lists[-1], lists[-2], lists[-3], lists[1], "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt"]:
        text = fetch_url(url)

        for line in text.splitlines():
            if re.search(r"\$.*\b(csp|generichide|popup|badfilter)\b", line):
                continue

            if line.startswith('@@'):
                allow.add(line)

    doc.difference_update(domains)


    # ensures item in adult sets, does not appear again
    adult_third_party, adult_specific, general_social, easy_privacy_specific, easy_privacy_general = (results.get('adult_third_party'), results.get('adult_specific'),
                                                         results.get('general_social_block'), results.get('easyprivacy_specific'),
                                                                                results.get('easyprivacy_general'))

    # print(len(check))
    for s in (straight_domains, third_party, customs, misc, scripts, allow) :
        s.difference_update(adult_third_party, adult_specific, general_social, easy_privacy_specific, easy_privacy_general)


    content = {
        "3p" : sorted(third_party),
        "adult_3p" : sorted([annotate_modifier(line, True) for line in adult_third_party]),
        "adult_specific" : sorted(adult_specific),
        "pattern" : sorted(customs),
        "misc" : sorted(misc | contains_all | contains_image | doc | csp),
        "scripts" : sorted(scripts),
        "general_social_block": sorted([annotate_modifier(line, True) for line in general_social]),
        "allow": sorted(allow),
        "specific_tracking": sorted(easy_privacy_specific),
        "general_tracking": sorted(easy_privacy_general),
        "general_newsletter" : sorted([annotate_modifier(line, True) for line in results.get('general_newsletter')]),
        "specific_newsletter" : sorted(results.get('specific_newsletter'))
    }

    return content


def just_anti_adblock(url):

    anti_allow, anti_block, third_server = set(), set(), set()
    content = fetch_url(url)

    if not content:
        return

    for line in content.splitlines():

        if line.startswith(('/^', '!', '$')) or '#' in line or 'generichide' in line or line == '[Adblock Plus 2.0]':
            continue

        if line.startswith('@@'):
            anti_allow.add(line)

        elif re.search(r"\$.*\b(third-party)\b", line):
            third_server.add(line)

        else:
            anti_block.add(line)


    return {
        "allow_anti" : sorted(anti_allow),
        "block_anti" : sorted(anti_block),
        "third_anti": sorted(third_server)
    }

# Builds static rules based on the malicious url list given
def redirect_static(dictionary : dict, json_dict : dict, redirect_domains: set) -> tuple :
    active, static_network, static_block = set(), [], []
    check = set()
    # print("Starting redirect job..")
    #
    # # Loads online malicious urls
    # live_data = fetch_url(json_dict.get('urlhaus_db'), json_mode= True)
    #
    # # Extract active hostnames from malicious database
    # active_hosts = {urlparse(entry[0]['url']).hostname for entry in live_data.values() if entry[0]['url_status'] == 'online'}
    #
    # # Load malicious domain list from urlhaus-filter
    # text = requests.get(dictionary.get('malicious')).text
    #
    # for line in text.splitlines():
    #     if line.startswith('!') or not line:
    #         continue
    #
    #     domain = line[2:][:-1]
    #
    #     # Cross-references malicious domains with online database
    #     if domain in active_hosts:
    #         check.add(domain)
    #         redirect_domains.add(line)

    print( len(redirect_domains) )
    for index, domain in enumerate(sorted(redirect_domains)) :

        url_filter, req_domain, mods = get_filter(domain)

        redirect_rule = {
            "id": index + 1,
            "priority": 1,
            "action": {
                "type": "redirect",
                "redirect": {
                    "extensionPath": f"/html/mainframe-redirect.html?blocked={url_filter}"
                }
            },
            "condition": {
                "urlFilter": url_filter,
                "resourceTypes": ["main_frame"]
            }
        }

        block_rule = {
            "id": index + 1,
            "priority": 1,
            "action": {"type" : "block"},
            "condition": {
                "urlFilter": url_filter,
                "resourceTypes": ["sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media",
                                  "websocket", "webtransport", "webbundle", "other"]
            }
        }

        if req_domain:
            for d in req_domain:
                redirect_rule['condition'].setdefault('requestDomains', []).append(d)


        # Populates list with the hardcoded rule
        static_network.append(redirect_rule)

        static_block.append(block_rule)


    return static_network, static_block
