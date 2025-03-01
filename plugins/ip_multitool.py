name = "IP Multitool"
id = 6969  # this is for later
enabled = True
author = "Alex Jenkins"
description = "Scan multiple IPs across multiple APIs"

from caseBuilder import insert_text
from plugins.ip_multitool_api_keys import (
    ABUSE_IPDB_API_KEY,
    IPDATA_API_KEY,
    IPINFO_ACCESS_TOKEN,
    VPN_API_KEY,
    VIRUSTOTAL_API_KEY,
    PROXYCHECK_API_KEY,
)
import requests, json, re


def scan_ip(ip):
    # Append API responses to a list for sorting later on
    unformatted_data = []

    unformatted_data.append(
        {
            "abuse_ipdb": get_data(
                "https://api.abuseipdb.com/api/v2/check",
                parameters={"ipAddress": ip},
                headers={"Accept": "application/json", "Key": ABUSE_IPDB_API_KEY},
            ),
        }
    )

    unformatted_data.append(
        {
            "ipdata": get_data(
                f"https://api.ipdata.co/{ip}/threat",
                parameters={"api-key": IPDATA_API_KEY},
            ),
        }
    )

    unformatted_data.append(
        {
            "ipinfo": get_data(
                f"https://ipinfo.io/{ip}",
                parameters={"token": IPINFO_ACCESS_TOKEN},
            ),
        }
    )

    unformatted_data.append(
        {
            "vpnapi": get_data(
                f"https://vpnapi.io/api/{ip}",
                parameters={"key": VPN_API_KEY},
            )
        }
    )

    unformatted_data.append(
        {
            "virustotal": get_data(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={
                    "accept": "application/json",
                    "x-apikey": VIRUSTOTAL_API_KEY,
                },
            )
        }
    )

    unformatted_data.append(
        {
            "proxycheck": get_data(
                f"https://proxycheck.io/v2/{ip}",
                parameters={
                    "vpn": 3,
                    "asn": 1,
                    "cur": 0,
                    "risk": 2,
                    "key": PROXYCHECK_API_KEY,
                },
            )
        }
    )

    return format_data(unformatted_data, ip)


def get_data(url, parameters=None, headers=None):
    # headers and parameters are none by default because they may not always be required by the APIs
    encoded_response = requests.request(
        method="GET",
        url=url,
        params=parameters,
        headers=headers,
    )

    decoded_response = json.loads(encoded_response.text)

    return decoded_response


def format_data(unformatted_data, ip):
    # Format the data into a structured dictionary for scalability
    formatted_data = {}
    formatted_data["tor_node"] = []
    formatted_data["vpn"] = []
    formatted_data["relay"] = []
    formatted_data["proxy"] = []

    for data in unformatted_data:

        if "abuse_ipdb" in data:

            working_data = data["abuse_ipdb"]["data"]
            formatted_data["public"] = working_data["isPublic"]

            # No further info is needed when IP is private so we can return early
            if not formatted_data["public"]:
                return formatted_data

            formatted_data["domain"] = working_data["domain"]
            formatted_data["isp"] = working_data["isp"]
            formatted_data["whitelisted"] = working_data["isWhitelisted"]
            formatted_data["confidence"] = working_data["abuseConfidenceScore"]
            formatted_data["usage"] = working_data["usageType"]

            if formatted_data["usage"] == "Reserved":
                return formatted_data

            formatted_data["abuse_reports"] = working_data["totalReports"]
            formatted_data["tor_node"].append(working_data["isTor"])

        elif "ipdata" in data:
            working_data = data["ipdata"]
            formatted_data["known_attacker"] = working_data["is_known_attacker"]
            formatted_data["known_abuser"] = working_data["is_known_abuser"]
            formatted_data["known_threat"] = working_data["is_threat"]
            formatted_data["bogon"] = working_data["is_bogon"]
            formatted_data["blocklists"] = working_data[
                "blocklists"
            ]  # can be removed in future
            formatted_data["tor_node"].append(working_data["is_tor"])
            formatted_data["relay"].append(working_data["is_icloud_relay"])
            formatted_data["proxy"].append(working_data["is_proxy"])

        elif "ipinfo" in data:
            working_data = data["ipinfo"]
            formatted_data["city"] = working_data["city"]
            formatted_data["region"] = working_data["region"]
            formatted_data["country"] = working_data["country"]

        elif "vpnapi" in data:
            working_data = data["vpnapi"]["security"]
            formatted_data["vpn"].append(working_data["vpn"])
            formatted_data["tor_node"].append(working_data["tor"])
            formatted_data["relay"].append(working_data["relay"])
            formatted_data["proxy"].append(working_data["proxy"])

        elif "virustotal" in data:
            working_data = data["virustotal"]["data"]["attributes"]
            formatted_data["malicious_count"] = working_data["total_votes"]["malicious"]
            # formatted_data["virustotal_reputation"] = working_data["reputation"]
            
        elif "proxycheck" in data:
            #print(data)
            working_data = data["proxycheck"][ip]
            formatted_data["asn"] = working_data["asn"]
            formatted_data["organisation"] = working_data["organisation"]
            formatted_data["proxycheck_risk_score"] = working_data["risk"]
            if working_data["proxy"] == 'yes':
                formatted_data["proxy"].append(True)
            if working_data["vpn"] == 'yes':
                formatted_data["vpn"].append(True)

    return formatted_data


def check_plural(value, single, plural):
    # A bit of a novel function that just helps with readability
    if value != 1:
        return plural
    else:
        return single


def check_total_abuse_reports(abuse_reports):
    modifier = check_plural(abuse_reports, "time", "times")
    if abuse_reports > 0:
        insert_text(f"    - Reported {abuse_reports} {modifier} for abuse")


def check_total_malicious_reports(malicious_reports):
    if malicious_reports > 0:
        insert_text(f"    - Deemed malicious by {malicious_reports} security vendors")


def assess_abuse_confidence(abuse_reports, confidence, proxycheck_risk_score):
    # Note: 66%+ confidence is matched in the reputation check
    combined_score = (confidence + proxycheck_risk_score) / 2
    insert_text(f"    - Probability this address is abusive: {round(combined_score)}%")
    check_total_abuse_reports(abuse_reports)


def defang(domain):
    if domain:
        defanged_domain = re.sub(r"\.", "[.]", domain)
        return defanged_domain
    else:
        return "Unknown"


def check_if_true(list_of_items):
    for item in list_of_items:
        if item:
            return True
    return False


def get_detections(data):

    detections = []

    tor_node = check_if_true(data["tor_node"])
    icloud_relay = check_if_true(data["relay"])
    proxy = check_if_true(data["proxy"])
    vpn = check_if_true(data["vpn"])
    bogon = data["bogon"]

    if tor_node:
        detections.append("TOR Node")

    if icloud_relay:
        detections.append("Relay")

    if proxy:
        detections.append("Proxy")

    if vpn:
        detections.append("VPN")

    if bogon:
        # Check to see if the address is illegitimate (not officially assigned by an internet registration institute)
        detections.append("Bogon")

    return detections


def get_reputation(data, confidence):

    reputation = []

    known_attacker = data["known_attacker"]
    known_abuser = data["known_abuser"]
    known_threat = data["known_threat"]
    malicious = data["malicious_count"] > 0  # return true if count greater than 0

    if malicious:
        reputation.append("Malicious")

    if known_abuser or confidence >= 66:
        reputation.append("Abusive")

    if known_attacker:
        reputation.append("Attacker")

    if known_threat:
        reputation.append("Threat")

    return reputation


def sort_blocklists(blocklists):

    formatted_blocklist = []

    for blocklist in blocklists:
        formatted_blocklist.append(blocklist["name"])

    return formatted_blocklist


def list_to_string(list):
    return ", ".join(list)


def check_if_address_is_public(data):
    if not data["public"] or data["usage"] == "Reserved":
        return False
    else:
        return True


def lookup(ip_address):

    data = scan_ip(ip_address)
    public_address = check_if_address_is_public(data)

    insert_text(f"[*] Reputation scan results for {ip_address}")

    if public_address:
        defanged_domain = defang(data["domain"])
        usage_type = data["usage"]
        isp = data["isp"]
        asn = data["asn"]
        organisation = data["organisation"]
        city = data["city"]
        region = data["region"]
        country = data["country"]

        insert_text(f"    - ASN: {asn}")
        insert_text(f"    - Domain: {defanged_domain}")
        insert_text(f"    - ISP: {isp} ({usage_type})")
        insert_text(f"    - Organisation: {organisation}")
        insert_text(f"    - Location: {city}, {region}. {country}.")

        abuse_reports = data["abuse_reports"]
        proxycheck_risk_score = data["proxycheck_risk_score"]
        malicious_reports = data["malicious_count"]
        confidence = data["confidence"]
        whitelisted = data["whitelisted"]
        blocklists = data["blocklists"]

        # Check to see if the address is whitelisted before doing an abuse check
        if whitelisted:
            insert_text("    - Whitelisted address")

        else:

            detections = get_detections(data)
            if detections:
                modifier = check_plural(len(detections), "Detection", "Detections")
                formatted_detections = list_to_string(detections)
                insert_text(f"    - {modifier}: {formatted_detections}")

            reputation = get_reputation(data, confidence)
            if reputation:
                formatted_reputation = list_to_string(reputation)
                insert_text(f"    - Reputation: {formatted_reputation}")
                check_total_abuse_reports(abuse_reports)
                check_total_malicious_reports(malicious_reports)

            if blocklists:
                # Check to see if the address is in any blocklists on ipdata
                modifier = check_plural(len(blocklists), "Blocklist", "Blocklists")
                stripped_blocklists = sort_blocklists(blocklists)
                formatted_blocklists = list_to_string(stripped_blocklists)
                insert_text(f"    - {modifier}: {formatted_blocklists}")

            elif not reputation and confidence > 0 and proxycheck_risk_score > 0:
                assess_abuse_confidence(abuse_reports, confidence, proxycheck_risk_score)

            elif not reputation and confidence == 0 and not blocklists:
                insert_text("    - Non-malicious")

    else:
        insert_text(f"    - Private/reserved")


def run():
    import tkinter as tk
    from tkinter import ttk
    import re

    class MultiTool:

        def __init__(self, menu):

            # variables
            self.menu = menu
            self.ip_addresses = []

            # text widgets
            self.input_field = tk.Text(menu)

            # buttons
            self.format_data_button = tk.Button(
                menu, text="Strip IPs", command=self.format_data
            )
            self.scan_ips_button = tk.Button(
                menu, text="Scan", command=self.scan_ip_addresses
            )

            # tags
            self.highlight_tag = "highlight"
            self.input_field.tag_configure(self.highlight_tag, foreground="red")

            # display widgets (geometry manager)
            self.input_field.pack()  # use a geometry manager to display widgets
            self.format_data_button.pack()
            self.scan_ips_button.pack()

            self.notebook = ttk.Notebook(menu, height=50, width=50)
            self.notebook.pack(fill="both", expand=True)

        def check_for_ip_addresses(self, text):

            ipv4_regex = r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
            ipv6_regex = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

            ipv4_addresses = re.findall(ipv4_regex, text)
            ipv6_addresses = [match.group() for match in re.finditer(ipv6_regex, text)]

            self.ip_addresses = ipv4_addresses + ipv6_addresses
            self.format_input()

        def format_input(self):

            self.input_field.delete("1.0", tk.END)
            for ip in self.ip_addresses:
                self.input_field.insert(tk.END, f"{ip}")

        def scan_ip_addresses(self):
            if self.ip_addresses:

                for ip_address in self.ip_addresses:
                    lookup(ip_address)

        def format_data(self):
            self.check_for_ip_addresses(self.input_field.get("1.0", "end"))
            pass

    # Create the main window
    menu = tk.Tk()
    menu.title("Multitool")

    # Start the Tkinter main loop
    MultiTool(menu)
