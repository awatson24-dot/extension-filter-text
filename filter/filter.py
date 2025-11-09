# This is a sample Python script.
import json
import re

from datetime import datetime
from .network import redirect_static, network_dynamic, just_anti_adblock
from .cookies import cookies_rules, cookie_static
from .cosmetics import cosmetic_filter
from .utils import further_remove, add_missing_modifier

url_dict = {
        "phishing" : "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
        "malicious" : "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt"
        }

# collection of different filter lists including AdGuard, Fanboy, uBlockOrigin uAssets and Yokoffing's filter lists
filter_lists = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://www.fanboy.co.nz/r/fanboy-ultimate.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://fanboy.co.nz/fanboy-antifonts.txt",
    "https://raw.githubusercontent.com/yokoffing/filterlists/refs/heads/main/block_third_party_fonts.txt",
    "https://raw.githubusercontent.com/theel0ja/CrapBlock/master/block-googlefonts.txt"
]

cosmetics = [
    "https://www.fanboy.co.nz/r/fanboy-ultimate.txt",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
    "https://filters.adtidy.org/extension/ublock/filters/14_optimized.txt",
    "https://raw.githubusercontent.com/yokoffing/filterlists/refs/heads/main/annoyance_list.txt"
]

custom_js_patterns = [
    # Logging & Tracking
    re.compile(r"/log(\?|[/?_.-]|$)", re.IGNORECASE),
    re.compile(r"/log(_event)?\.?(js|gif)?$", re.IGNORECASE),
    re.compile(r"/fp_204(\?|$)", re.IGNORECASE),
    re.compile(r"/track(ers?|_event)?(\.js)?", re.IGNORECASE),
    re.compile(r"/tracking(\.js)", re.IGNORECASE),
    re.compile(r"/trace(\.js)?", re.IGNORECASE),
    re.compile(r"/event(s)?(\.js)?", re.IGNORECASE),
    re.compile(r"/collect(\.js)?", re.IGNORECASE),
    re.compile(r"/beacon(\.js)?", re.IGNORECASE),
    re.compile(r"/metrics(\.js)?", re.IGNORECASE),
    re.compile(r"/telemetry(\.js)?", re.IGNORECASE),
    re.compile(r"/measure(\.js)?", re.IGNORECASE),
    re.compile(r"[/?_.-]hit(\.js)", re.IGNORECASE),
    re.compile(r"/ping(\?|[/?_.-]|$)", re.IGNORECASE),

    # Pixels, Conversions, Impressions
    re.compile(r"/(pixel|impression|conversion)\.gif", re.IGNORECASE),
    re.compile(r"/fb_pixel", re.IGNORECASE),

    # Ad scripts and redirections
    re.compile(r"/pagead/", re.IGNORECASE),
    re.compile(r"/(ad(frame|s|server|sense)|banner(s)?)(\.js)", re.IGNORECASE),
    re.compile(r"/(redir(ect)?|out|exit)(\.php)?([/?#]|$)", re.IGNORECASE),

    # Click tracking
    re.compile(r"/click([/?#]|$|\.(gif|php|js))", re.IGNORECASE),

    # Social trackers
    re.compile(r"/(linkedin|twitter)\.js", re.IGNORECASE),

    # Google/Analytics
    re.compile(r"/(ga|gtm|analytics|stat(s))(\.js)", re.IGNORECASE),
    re.compile(r"/jslog", re.IGNORECASE),

    # A/B Testing / Personalization
    re.compile(r"/(ab_test|split(_test)?|experiment)\.js", re.IGNORECASE),

    # Consent / Subscription / Email
    re.compile(r"/(subscribe(_form)?|email_capture|consent_manager|cookie(consent|_banner)?)\.js", re.IGNORECASE),
    re.compile(r"/verify/", re.IGNORECASE),

    # Popups / Interstitials / Layers
    re.compile(r"/(pop|layer|interstitial)\.js", re.IGNORECASE),

    # Fingerprinting and advanced tracking
    re.compile(r"/(fingerprint|client_hints|device_info|browser_fingerprint)\.js", re.IGNORECASE),

    # SDKs, Libraries, Initializers
    re.compile(r"/(init|sdk)\.js", re.IGNORECASE),
    re.compile(r"/js/ads", re.IGNORECASE),

    # Suspicious short scripts (x.js, t.js, s.js)
    re.compile(r"/[xts]\.js$", re.IGNORECASE),

    # common in malware/obfuscation
    re.compile(r"/[a-z0-9]{10,}\.js$", re.IGNORECASE),
]

valid_jsons = {
    "duckduckgo" : "https://raw.githubusercontent.com/duckduckgo/tracker-radar/refs/heads/main/build-data/generated/domain_summary.json",
    "urlhaus_db" : "https://urlhaus.abuse.ch/downloads/json_online/"
}

def gen_filter():
    # global set for all domain
    master_domain = set()

    dynamic_rules = network_dynamic(lists=filter_lists, patterns=custom_js_patterns, json_dict=valid_jsons,
                                    domains= master_domain, min_prev= 0.005)

    # get cookie filters from Fanboy Cookie Monster
    remove_cookies = cookies_rules(url= "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt")

    third_cookies = remove_cookies.get('third_party_cookies')

    # get cosmetic filters from Fanboy Ultimate List
    all_cosmetics = cosmetic_filter(lists= cosmetics)

    # remove cookie repetition from dynamic rules
    dynamic_rules['3p'] = [item for item in dynamic_rules.get('3p') if item not in remove_cookies.get('third_party_cookies')]
    dynamic_rules['pattern'] = [item for item in dynamic_rules.get('pattern') if item not in remove_cookies.get('dynamic_cookies')]
    dynamic_rules['scripts'] = [item for item in dynamic_rules.get('scripts') if item not in remove_cookies.get('dynamic_cookies')]

    everything = further_remove(list1= dynamic_rules['misc'], list2= master_domain)

    # gets anti-block filters
    remove_anti = just_anti_adblock(url= "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt")

    # updates the modifiers for third-party cookies
    third_cookies = [add_missing_modifier(f) for f in third_cookies]

    with open("adnante-filter.txt", "w", encoding= "utf-8") as f:
        f.write('! Title: ADNante Filter List\n')
        f.write('! Description: A compilation of commonly used block list in one file to comply with limits\n')
        f.write(f"! Updated: {datetime.now().strftime('%c')} (Daily Frequency)\n")
        f.write('!\n! easylist_cookie_general_block.txt\n!\n')
        f.write('\n'.join(remove_cookies.get('dynamic_cookies')) + '\n')
        f.write('!\n! easylist_cookie_specific_block.txt\n!\n')
        f.write('\n'.join(remove_cookies.get('specific_block')) + '\n')
        f.write('!\n! easylist_cookie_thirdparty.txt\n!\n')
        f.write('\n'.join(third_cookies) + '\n')
        f.write('!\n! easyprivacy_general.txt \n!\n')
        f.write('\n'.join(dynamic_rules.get('general_tracking')) + '\n')
        f.write('!\n! easyprivacy_specific.txt \n!\n')
        f.write('\n'.join(dynamic_rules.get('specific_tracking')) + '\n')
        f.write('!\n! adult_third_party.txt \n!\n')
        f.write('\n'.join(dynamic_rules.get('adult_3p')) + '\n')
        f.write('!\n! adult_specific_block.txt \n!\n')
        f.write('\n'.join(dynamic_rules.get('adult_specific')) + '\n')
        f.write('!\n! general_third_party.txt includes xmlhttprequest \n!\n')
        f.write('\n'.join(dynamic_rules.get('3p')) + '\n')
        f.write('!\n! domain_level.txt, may include document, all modifiers\n!\n')
        f.write('\n'.join(sorted( master_domain )) + '\n')
        f.write('!\n! script.txt\n!\n')
        f.write('\n'.join(dynamic_rules.get('scripts')) + '\n')
        f.write('!\n! misc.txt contains fonts, popups, media, images, sub- and document, all remaining resource types\n!\n')
        f.write('\n'.join(sorted( everything )) + '\n')
        f.write('!\n! custom_tracking_pattern.txt\n!\n')
        f.write('\n'.join(dynamic_rules.get('pattern')) + '\n')
        f.write('!\n! newsletter_general_block.txt\n!\n')
        f.write('\n'.join(dynamic_rules.get('general_newsletter')) + '\n')
        f.write('!\n! fanboy_newsletter_specific_block.txt\n!\n')
        f.write('\n'.join(dynamic_rules.get('specific_newsletter')) + '\n')
        f.write('!\n! social_general_block.txt\n!\n')
        f.write('\n'.join(dynamic_rules.get('general_social_block')) + '\n')
        f.write('!\n! anti_adblock_blocklist.txt\n!\n')
        f.write('\n'.join(remove_anti.get('block_anti')) + '\n')
        f.write('!\n! anti_adblock_third_party.txt\n!\n')
        f.write('\n'.join(remove_anti.get('third_anti')) + '\n')
        f.write('!\n! anti_adblock_allowlist.txt\n!\n')
        f.write('\n'.join(remove_anti.get('allow_anti')) + '\n')
        f.write('!\n! general_allowlist.txt\n!\n')
        f.write('\n'.join(dynamic_rules.get('allow')) + '\n')
        f.write('!\n! general_hide.txt\n!\n')
        f.write('\n'.join(all_cosmetics.get('general_hide')) + '\n')
        f.write('!\n! specific_hide.txt\n!\n')
        f.write('\n'.join(all_cosmetics.get('specific_hide')) + '\n')
        f.write('!\n! allowlist_hide.txt\n!\n')
        f.write('\n'.join(all_cosmetics.get('allow_cosmetic')))


# print(example('https://en.wikipedia.org/wiki/History_of_Python')[1])

gen_filter()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
