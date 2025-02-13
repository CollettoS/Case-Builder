from        datetime import datetime
import      csv

def read_settings_debug(csv_file="1"):
    settings = {}
    csv_file = f"config.csv"
    with open(csv_file, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            settings[row['setting_name']] = row['setting_value']
    return settings

def write_debug(action: str):
    settings = read_settings_debug("config.csv")
    if settings.get("debug_mode") == "True":
        date_str = datetime.now().strftime("%Y-%m-%d")
        filename = f"debug_{date_str}.txt"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(filename, "a") as file:
            file.write(f"{timestamp} - {action}\n")
    else:
        return