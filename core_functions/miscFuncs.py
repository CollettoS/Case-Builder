import      pycountry
from settings.debug import write_debug
import webbrowser

def get_country_name(country_code):
    try:
        write_debug(f"Country Name called with {country_code}")

        country = pycountry.countries.get(alpha_2=country_code)
        write_debug(f"Country name found as: {country.name}")

        return country.name if country else "Unknown"
    except KeyError:
        return "Unknown"

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

