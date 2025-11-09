import requests

from utils import fetch_url


def cosmetic_filter(lists):

    general_cosmetic, specific_cosmetic, allow_cosmetic = set(), set(), set()

    for url in lists :

        content = fetch_url(url)
        if not content:
            continue

        for line in content.splitlines():
            if line.startswith('!'):
                continue
            if line.startswith('##'):
                general_cosmetic.add(line)
            elif '##' in line:
                specific_cosmetic.add(line)
            elif '#@#' in line:
                allow_cosmetic.add(line)

    return {
        'general_hide' : sorted(general_cosmetic),
        'specific_hide' : sorted(specific_cosmetic),
        'allow_cosmetic' : sorted(allow_cosmetic)
    }