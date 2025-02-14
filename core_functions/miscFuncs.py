import      pycountry
from settings.debug import write_debug
import webbrowser
import re


def get_country_name(country_code):
    try:
        write_debug(f"Country Name called with {country_code}")

        country = pycountry.countries.get(alpha_2=country_code)
        write_debug(f"Country name found as: {country.name}")

        return country.name if country else "Unknown"
    except KeyError:
        return "Unknown"

def sanitize_urls(note_area):
    """Finds and replaces all URLs in the note_area with a safe format."""
    text = note_area.get("1.0", "end")  # Get all text from the note area
    url_pattern = r"\b(?:https?://)?(?:www\.)?([\w.-]+\.[a-z]{2,})\b"  # Regex to match URLs

    def replace_url(match):
        return match.group(1).replace(".", "[.]")  # Convert google.com → google[.]com

    sanitized_text = re.sub(url_pattern, replace_url, text)  # Replace URLs in text

    note_area.delete("1.0", "end")  # Clear existing text
    note_area.insert("1.0", sanitized_text)  # Insert sanitized text back


def open_github():
    webbrowser.open("https://github.com/CollettoS/Case-Builder")  

def bug_report():
    webbrowser.open("https://github.com/CollettoS/Case-Builder/issues")  

def open_help():
    webbrowser.open("https://github.com/CollettoS/Case-Builder/blob/main/README.md")  

def msg_dev():
    webbrowser.open("https://github.com/CollettoS/Case-Builder/discussions")  

def submit_idea():
    webbrowser.open("https://github.com/CollettoS/Case-Builder/discussions/categories/ideas")  

