import      pycountry
from settings.debug import write_debug


def get_country_name(country_code):
    try:
        write_debug(f"Country Name called with {country_code}")

        country = pycountry.countries.get(alpha_2=country_code)
        write_debug(f"Country name found as: {country.name}")

        return country.name if country else "Unknown"
    except KeyError:
        return "Unknown"
    