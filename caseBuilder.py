import      customtkinter as ctk
from        tkinter         import      messagebox, ttk, font, filedialog, Menu
import      tkinter as tk  # Importing standard Tkinter for Menu
import      tkinter.font as font
import      os
from        tkinter import messagebox
import      webbrowser
import      csv
import      requests
import      re
from        datetime import datetime
import      random
from        core_functions.miscFuncs import get_country_name
from        core_functions.version_control import compare_versions
from        core_functions.case_entities import entitity_manager_window
from        settings.debug import write_debug as log_debug_action
from        core_functions.settings_window import open_settings_menu
import      importlib.util
from        spellchecker    import      SpellChecker
import      core_functions.miscFuncs

FOLDER_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'saved_notes')

os.chdir(os.path.dirname(os.path.abspath(__file__)))
spell = SpellChecker()
case_entities_list = {}
root = None
# Debugging ->
# Templates:
# log_debug_action("")
# log_debug_action(f"")
# FC: = Function called 
# e.g. log_debug_action(f"FC: Scan IP, IP to scan: {ip}")

# Satus Menu Functions
# Flash status bar
def flash_status(message, duration=5000):  # Duration in milliseconds
    # Flash the status message between red and orange for a specified duration
    def toggle_flash(counter=0):
        if counter < duration / 500:  # Duration divided by 500ms toggle interval
            current_color = status_label.cget("bg_color")
            if current_color == "#f44336":  # Red
                status_label.configure(bg_color="#ff9800")  # Orange
                top_frame.configure(fg_color="#ff9800")

            else:
                status_label.configure(bg_color="#f44336")  # Red
                top_frame.configure(fg_color="#f44336")  

            status_label.after(500, toggle_flash, counter + 1)  # Increment counter

        else:
            # Stop flashing by setting a final color (optional)
            status_label.configure(bg_color="#ff9800")
            top_frame.configure(fg_color="#ff9800")


    status_label.configure(text=message, bg_color="#ffffff")  # Set the message text
    toggle_flash()  # Start flashing
# Updates the status message 
def update_status_message(message, message_type="info"):
    log_debug_action(f"Update status message: {message} type: {message_type}")
    if message_type == "success":
        status_label.configure(text=message, bg_color="#4CAF50")  # Green for success
        top_frame.configure(fg_color="#4CAF50")  # Green for success
    elif message_type == "error":
        status_label.configure(text=message, bg_color="#f44336")  # Red for error
        top_frame.configure(fg_color="#f44336")  

    elif message_type == "warning":
        status_label.configure(text=message, bg_color="#ff9800")  # Orange for warning
        top_frame.configure(fg_color="#ff9800")
    elif message_type == "flash":
        log_debug_action(f"Flash status started")
        flash_status(message)  # Flash effect for "flash"
    else:
        status_label.configure(text=message, bg_color="#333333")  # Default color for info
        top_frame.configure(fg_color="#333333")


# File Functions
# Search files
def search_files(type=1, search="None", ent_type="Unkown"):
    times_found = 0
    log_debug_action(f"Search Files Function called - Type: {type} - Search: {search}")
    if type == 1:
        search_term = search_entry.get()  # Get the search term from the search bar
    elif type == 2:
        search_term = search
    log_debug_action(f"Seatch Files - Option: {type}")
    if not os.path.isdir(FOLDER_PATH):
        log_debug_action(f"Search Files ERROR - Invalid folder path")
        messagebox.showerror("Error", "Invalid folder path!")
        return
    
    matching_files = []
    results_list.delete(0, tk.END)

    for root, dirs, files in os.walk(FOLDER_PATH):  # Walk through the folder
        for file in files:
            # Check if the search term is in the file name
            if search_term.lower() in file.lower():
                matching_files.append(os.path.join(root, file))  # Store full file path
            else:
                # Check if the search term is in the file content
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        if search_term.lower() in f.read().lower():
                            matching_files.append(os.path.join(root, file))  # Store full file path
                            times_found =+ 1
                            continue
                except:
                    continue  # If there's an error reading the file, skip it
    if type==1:
        # Display the results
        if matching_files:
            for file in matching_files:
                results_list.insert(tk.END, os.path.basename(file))  # Display only file name in the list
        else:
            messagebox.showinfo("No Results", "No files matched the search term!")
    elif type==2:
        add_row(ent_type, search_term, f"{times_found} times", "")
        if matching_files:
            update_status_message(f"{search_term}: observed before!","flash")
# Open file from results list
def open_file(event):
    # Get the selected file name
    log_debug_action(f"Open File function called")
    try:
        selected_file = results_list.get(results_list.curselection())
        if selected_file:
            # Find the full path of the selected file
            file_path = None
            for root, dirs, files in os.walk(FOLDER_PATH):
                for file in files:
                    if file == selected_file:
                        log_debug_action(f"File opened")
                        file_path = os.path.join(root, file)
                        break
                if file_path:
                    break
            
            if file_path:
                try:
                    # Open the file using the default application for its type
                    webbrowser.open(file_path)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to open file: {e}")
                    log_debug_action(f"ERROR: Failed to open file:  {e}")

            else:
                messagebox.showerror("Error", "File not found.")
                log_debug_action(f"ERROR: File not found")

        else:
            log_debug_action(f"ERROR: NO FILE SELECTED")

            messagebox.showerror("Error", "No file selected.")
    except IndexError:
        messagebox.showerror("Error", "Please select a file.")
        log_debug_action(f"ERROR: NO FILE SELECTED")

# Function that reads dropdown menu options drom data.csv
def load_csv_data(filename):
    dropdown_values = []
    corresponding_values = []
    update_status_message("Reading CSV...","info ")
    with open(filename, newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            # Check if the first column contains '1'
            if row[0] == '1':
                dropdown_values.append(row[1])  # First column for the dropdown 
                corresponding_values.append(row[2])  # Second column for the value to insert
                update_status_message("CSV Read...","info")
    return dropdown_values, corresponding_values
# read the config.csv file to get user settings
def read_settings(csv_file="config.csv"):
    settings = {}
    csv_file = f"{csv_file}"
    with open(csv_file, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            settings[row['setting_name']] = row['setting_value']
    return settings

def open_saved_note_menu_func():
    # Open file dialog to select a .txt file
    log_debug_action(f"Open Saved Note function called")
    file_path = filedialog.askopenfilename(
        title="Open Text File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "r") as file:
                log_debug_action(f"File opened")
                content = file.read()
            # Clear the text area and insert the file content
            note_area.delete(1.0, tk.END)
            note_area.insert(tk.END, content)
        except Exception as e:
            log_debug_action(f"OPen saved note ERROR: {e}")
            messagebox.showerror("Error", f"Failed to open file: {e}")

def load_plugins(menu):
    plugins_folder = "plugins"
    plugin_count = 0
    if not os.path.exists(plugins_folder):
        os.makedirs(plugins_folder)

    menu.delete(0, tk.END)  # Clear existing menu items

    for file in os.listdir(plugins_folder):
        if file.endswith(".py"):
            plugin_path = os.path.join(plugins_folder, file)
            plugin_name = file[:-3]  # Remove .py extension

            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "enabled") and getattr(module, "enabled") and hasattr(module, "run"):
                tool_name = getattr(module, "name", plugin_name)
                menu.add_command(label=tool_name, command=module.run)
                plugin_count =+ 1
            else:
                # print(f"Skipping {file}: Missing 'enabled' or 'run' function.")
                log_debug_action(f"Load Plugins: Skipping {file}: Missing 'enabled' and/or 'run' function.")
    if plugin_count == 0:
        menu.add_command(label="No Plugins!", command=None)
    


# Adding info
# Add user, role and email
def add_user():
    log_debug_action(f"Add User Function called")
    user = user_entry.get()
    role = role_entry.get()
    email = email_entry.get()
    topText = topvalue.get()
    if user == "Enter user":
        user = ""
    if role == "Enter role":
        role = ""
    if email == "Enter email":
        email = ""
    user_text = ""
    if user:
        user_text += f"\nUser:\t\t\t{user}"
        log_debug_action(f"User - {user}")
        line = 1
    if role:
        user_text += f"\nRole:\t\t\t{role}"
        log_debug_action(f"Role - {role}")
        if user:
            line = 1
        else: 
            line = 2
    if email:
        user_text += f"\nEmail:\t\t\t{email}"
        log_debug_action(f"Email - {email}")
        if user:
            line = 1
        elif role:
            line = 2
        else: 
            line = 3

    if user or role or email:
        # Check if there is existing text in the note area
        existing_text = note_area.get("1.0", "end").strip()
        if topText:
            # Insert user info at the top
            log_debug_action(f"Text sent to insert_text with postion top")
            insert_text(user_text, position="top")
        else:
            log_debug_action(f"Text sent to insert_text with postion default")
            insert_text(user_text)
        user_entry.delete(0, tk.END)
        role_entry.delete(0, tk.END)
        email_entry.delete(0, tk.END)
        log_debug_action(f"User, email and role entry cleared")
    if user:
        search_files(2, user, "User")
    if email:
        search_files(2, email, "Email")

# Add host
def add_host():
    host = host_entry.get()
    host_text = f"Host:\t\t\t{host}\n"
    log_debug_action(f"Add host {host}")
    insert_text(host_text)
    search_files(2, host, "Host")
    host_entry.delete(0, tk.END)
    log_debug_action(f"Host entry cleared")

# Add email info
def add_info(info_type, entry_widget):
    info_value = entry_widget.get()
    if info_value:
        log_debug_action(f"Add Info: {info_type}")
        if info_type:
            match info_type:
                case "sender":
                    sender_text = f"Sender:\t\t\t{info_value}\n"
                    insert_text(sender_text)
                    emailSender.delete(0, ctk.END)
                case "recipient":
                    recipient_text = f"Recipient:\t\t\t{info_value}\n"
                    insert_text(recipient_text)
                    emailRecipient.delete(0, ctk.END)
                case "subject":
                    subject_text = f"Subject:\t\t\t{info_value}\n"
                    insert_text(subject_text)
                    emailSubject.delete(0, ctk.END)
                case "attachments":
                    attachments_text = f"Attachments:\t\t\t{info_value}\n"
                    insert_text(attachments_text)
                    emailAttachments.delete(0, ctk.END)
                case _:
                    update_status_message("Error: Info type unknown", "error")
            search_files(2, info_value, info_type)

# Function used to format and insert all inputs into the text area
def insert_text(formatted_text, position="default"):
    log_debug_action(f"Text Insert: {formatted_text} - Position: {position}")
    if position == "top":
        note_area.insert("1.0", formatted_text + "\n")
    elif position == "end":
        note_area.insert(tk.END, formatted_text + "\n")
    else:
        note_area.insert(tk.END, formatted_text + "\n")

def insert_corresponding_value():
    # Get the selected item from the dropdown
    selected_item = dropdown.get()
    
    # Find the index of the selected item
    try:
        index = dropdown_values.index(selected_item)
        # Get the corresponding value from the right (second column)
        value_to_insert = corresponding_values[index]
        # Insert the value into the text area
        insert_text(value_to_insert, "end")
    except ValueError:
        update_status_message("Error: No values found in CSV!","error")

# Scans
# Basic IP scan using abuseipdb
def scan_ip():

    ip = ip_entry.get().strip()
    log_debug_action(f"Scan IP started")
    if not ip:
        update_status_message("Error: Please enter a valid IP","error")
        log_debug_action(f"Scan IP: No IP")
        ip_entry.delete(0, tk.END)
        log_debug_action(f"IP input cleared")

        return

    try:
        api1 = str(settings.get("abuseipdb_api")).strip()
        #print(api1)
        api_key = api1
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()

        data = response.json()["data"]
        abuse_score = data.get("abuseConfidenceScore", 0)
        suspicious_label = " - suspicious" if abuse_score > 70 else ""


        update_status_message(f"IP: {ip} has been checked successfully!","success")
        log_debug_action(f"IP: {ip} has been scanned")
        formatted_text = f"IP:\t\t\t{ip}{suspicious_label}\n"
        abuseConfidenceScore = data.get("abuseConfidenceScore", "N/A")
        countryCode     = data.get("countryCode", "N/A")
        usageType       = data.get("usageType", "N/A")
        isp             = data.get("isp", "N/A")
        domain          = data.get("domain", "N/A")
        hostnames       = data.get("hostnames", "N/A")
        isTor           = data.get("isTor", "False")
        totalReports    = data.get("totalReports", "N/A")
        lastReportedAt  = data.get("lastReportedAt", "N/A")
        countryName = get_country_name(countryCode)

        
        formatted_text += f"Abuse Confidence:\t\t\t{abuseConfidenceScore}\n"
        formatted_text += f"Reports:\t\t\t{totalReports}\n"
        formatted_text += f"Last Report:\t\t\t{lastReportedAt}\n"
        formatted_text += f"Country:\t\t\t{countryName} - {countryCode}\n"
        formatted_text += f"Usage Type:\t\t\t{usageType}\n"
        formatted_text += f"ISP:\t\t\t{isp}\n"
        formatted_text += f"Domain:\t\t\t{domain}\n"
        formatted_text += f"Hostnames:\t\t\t{hostnames}\n"
        formatted_text += f"TOR?:\t\t\t{isTor}\n"


        formatted_text += "\n"
        insert_text(formatted_text)
        search_files(2, ip, "IP")

        ip_entry.delete(0, tk.END)
        log_debug_action(f"IP Scan finished - IP entry cleared")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to scan IP: {e}")
        log_debug_action(f"IP Scan ERROR: {e}")
# scan file hash using VT
def scan_hash():
    file_hash = hash_entry.get().strip()
    log_debug_action(f"Scan hash started")
    if not file_hash:
        update_status_message("Please enter a valid hash","error ")

        return

    try:
        api2 = str(settings.get("vt_api")).strip()

        api_key = api2
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        
        headers = {
            "x-apikey": api_key
        }

        response = requests.get(url, headers=headers)
        
        if response.status_code == 404:
            messagebox.showerror("Error", "File hash not found in VirusTotal.")
            hash_entry.delete(0, tk.END)
            log_debug_action(f"Hash Error - Not found")
            log_debug_action(f"Hash Entry cleared")
            return
        
        response.raise_for_status()  # Check for other HTTP errors
        
        data = response.json()["data"]["attributes"]

        # General Information
        file_name = data.get("meaningful_name", "N/A")
        file_size = data.get("size", "N/A")
        file_type = data.get("type_extension", "N/A")
        file_type2 = data.get("type_tags", "N/A")
        file_author = data.get("author", "N/A")  # Get author (publisher) info
        file_magic = data.get("magic", "N/A")  # File magic type
        file_trid = data.get("trid", "N/A")  # File TrID
        
        file_type += f" - {file_type2}"

        # Suspicious file label (if malicious detections exist)
        last_analysis_results = data["last_analysis_results"]
        malicious_found = False
        malicious_details = ""

        for engine, result in last_analysis_results.items():
            if result["category"] == "malicious":
                malicious_found = True
                malicious_details += f"{engine}: {result['result']}\n"

        formatted_text = f"File Hash:\t\t\t{file_hash}\n"
        formatted_text += f"File Name:\t\t\t{file_name}\n"
        formatted_text += f"File Size:\t\t\t{file_size} bytes\n"
        formatted_text += f"File Type:\t\t\t{file_type}\n"
        formatted_text += f"Author:\t\t\t{file_author}\n"
        formatted_text += f"Magic:\t\t\t{file_magic}\n"
        formatted_text += f"TrID:\t\t\t{file_trid}\n"


        # If malicious, display details
        if malicious_found:
            formatted_text += "\nMalicious Detections:\n"
            formatted_text += malicious_details.strip()  # Strip trailing newline
            log_debug_action(f"Hash has malicicous detections")
        else:
            formatted_text += "\nNo Malicious Detections\n"
        
        formatted_text += "\n"
        log_debug_action(f"Hash scanned {file_hash} finished")
        insert_text(formatted_text)
        search_files(2, file_hash, "Hash")

        hash_entry.delete(0, tk.END)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to scan file hash: {e}")
        log_debug_action(f"Hash error {e}")

# Logic functions 
# Populate the case menu
def populate_cases_menu():
    global cases_menu  

    folder_path = "open_cases"  # Path to the folder
    cases_menu.delete(0, tk.END)  # Clear the menu first
    try:
        # Get the list of files in the folder
        files = os.listdir(folder_path)
        if files:
            for file_name in files:
                # Add each file name as a menu item
                cases_menu.add_command(
                    label=file_name,
                    command=lambda name=file_name: open_case(name)
                )
            cases_menu.add_separator()
            cases_menu.add_command(label="Add new case", command=add_new_case)
        else:
            cases_menu.add_command(label="No cases available", state=tk.DISABLED)
            cases_menu.add_separator()
            cases_menu.add_command(label="Add new case", command=add_new_case)
    except FileNotFoundError:
        folder_path = "open_cases"
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            populate_cases_menu()
        else:
            messagebox.showerror("Error", f"Folder '{folder_path}' not found.")
            cases_menu.add_command(label="Folder not found", state=tk.DISABLED)
# Reads data.csv for the dropdown 
def load_csv_data(filename="settings/data.csv"):
    # Read the CSV and return two lists: one for dropdown values and one for corresponding values to insert
    dropdown_values = []
    corresponding_values = []
    update_status_message("Reading CSV...","info ")

    with open(filename, newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            # Check if the first column contains '1'
            if row[0] == '1':
                dropdown_values.append(row[1])  # First column for the dropdown 
                corresponding_values.append(row[2])  # Second column for the value to insert
                update_status_message("CSV Read...","info")
    return dropdown_values, corresponding_values
# For opening, open cases from the my cases menu
def open_case(file_name):
    change_case()
    file_path = os.path.join("open_cases", file_name)
    try:
        with open(file_path, "r") as f:
            content = f.read()
        note_area.delete(1.0, tk.END)
        title_entry.delete(0, tk.END)
        case_name = file_name.replace(".txt", "")

        note_area.insert(tk.END, content)
        title_entry.insert(tk.END, case_name)
    except Exception as e:
        messagebox.showerror("Error", f"Could not open {file_name}: {e}")
# checks if the case is open during the saving process 
def is_case_open(folder_path, file_name):
    log_debug_action(f"FL: Is case open")

    file_path = os.path.join(folder_path, file_name)
    return os.path.isfile(file_path)

def check_spelling():
    read_settings("config.csv")
    if settings.get("spell_check") == "True":
        text_content = note_area.get("1.0", tk.END).strip()

        # Clear previous highlights
        note_area.tag_remove("misspelled", "1.0", tk.END)

        # Split text into words and filter out excluded cases
        words = text_content.split()
        filtered_words = []
        for word in words:
            # Skip numbers
            if word.isdigit():
                continue
            # Skip IP addresses
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", word):
                continue
            # Skip words ending with punctuation
            if re.match(r".*[\.\,\!\?]$", word):
                filtered_words.append(word[:-1])  # Strip the punctuation and check the root word
            else:
                filtered_words.append(word)

        # Find misspelled words
        misspelled_words = spell.unknown(filtered_words)

        # Highlight all misspelled words
        for word in misspelled_words:
            start_idx = "1.0"
            while True:
                start_idx = note_area.search(word, start_idx, tk.END)
                if not start_idx:
                    break
                end_idx = f"{start_idx}+{len(word)}c"
                note_area.tag_add("misspelled", start_idx, end_idx)
                start_idx = end_idx

        # Configure tag for highlighting
        note_area.tag_config("misspelled", underline=True, foreground="red")

    else:
        note_area.tag_remove("misspelled", "1.0", tk.END)

    # Schedule the next check after 3 seconds
    root.after(3000, check_spelling)


# Button Functions
# Next case 
def next_case():
    log_debug_action(f"FL: Next Case")
    saved = save_note(1)
    if saved:
        log_debug_action(f"Next Case: Save logged")
        clear_input()
        update_status_message(f"Note area cleared! - File saved as: {saved}","success")

# Clear input area 
def clear_input():
    note_area.tag_remove("highlight", "1.0", "end")  # Remove old highlights

    note_area.delete(1.0, tk.END)
    title_entry.delete(0, tk.END)
    delete_rows()
    case_entities_list.clear()
    update_status_message("Note area cleared!","warning")

def add_new_case():
    saved = save_note(3)
    if saved:
        clear_input()
        update_status_message(f"New case! Note saved to your cases","success")
        populate_cases_menu()

def save_note(type):
    # 1 - Standard save, either case name or date + random numbers, can go to type 4 if active case
    # 2 - Save AS
    # 3 - Save as active case 
    # 4 - Active case removed, saved to cases folder
    # Get the content from the text area
    log_debug_action(f"FL: Save Note - Type: {type}")
    note_content = note_area.get("1.0", tk.END).strip()  # Grab all text from the area, excluding any trailing newlines
    case_name = title_entry.get().strip() # Get case name (e.g. MALWARE DETECTED BLA BLA)

    open_folder = "open_cases"
    case_name_to_find = (f"{case_name}.txt")

    if is_case_open(open_folder, case_name_to_find):
        if type == 1:
            type = 4
        
    if note_content:  # Only save if there is content
        # Define the folder to save the file 
        folder_path = "saved_notes"
        today_date = datetime.today().strftime('%d-%m-%Y')

        # Create the folder if it doesn't exist
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        if type == 1:
            folder_path = "saved_notes"

            if case_name:
                file_name = f"{case_name}-{today_date}.txt"
                file_path = os.path.join(folder_path, file_name)

            else:
                # Generate a three-digit random number
                random_number = random.randint(100, 999)
                file_name = f"{today_date}-{random_number}.txt"
                file_path = os.path.join(folder_path, file_name)
            update_status_message(f"Content saved! File: {file_path}","success")
        if type == 2:
            folder_path = "saved_notes"
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            update_status_message(f"Content saved! File: {file_path}","success")
        if type == 3:
            folder_path = "open_cases"
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
            if case_name:
                file_name = f"{case_name}.txt"
                file_path = os.path.join(folder_path, file_name)
            else:
                # Generate a three-digit random number
                random_number = random.randint(100, 999)
                file_name = f"{today_date}-{random_number}.txt"
                file_path = os.path.join(folder_path, file_name)
        if type == 4:
            folder_path = "saved_notes"
            if case_name:
                file_name = f"{case_name}-{today_date}.txt"
                file_path = os.path.join(folder_path, file_name)
            else:
                # Generate a three-digit random number
                random_number = random.randint(100, 999)
                file_name = f"{today_date}-{random_number}.txt"
                file_path = os.path.join(folder_path, file_name) 
                file_path = os.path.join(folder_path, file_name)

            del_file_path = os.path.join("open_cases", case_name_to_find)
            try:
                os.remove(del_file_path)
            except FileNotFoundError:
                update_status_message(f"Error: File not found", "error")
            except Exception as e:
                update_status_message(f"Error deleting file: {e}", "error")    
            populate_cases_menu()


        with open(file_path, "w") as file:
            file.write(note_content)  # Save the content to the file
            return file_path
    else:
        return False

def change_case():
    content = note_area.get("1.0", tk.END).strip()
    log_debug_action(f"FL: Change Case")
    if content:
        log_debug_action(f"Change case content found")
        save_note(3)
    else:
        log_debug_action(f"No content found")
    populate_cases_menu()

def copy_to_clipboard():
    # Get the content of the Text widget
    log_debug_action(f"Copy To Clipboard Function called")
    text_content = note_area.get("1.0", tk.END)  
    root.clipboard_clear()  # Clear the clipboard before adding new content
    root.clipboard_append(text_content)  # Append the content to the clipboard
    root.update()
    update_status_message("Content copied to clipboard!","success")
    note_area.configure(fg_color="#9ae6a6")
    log_debug_action(f"CTC - Note area cleared")
    note_area.after(500, lambda: note_area.configure(fg_color="#2d2d44"))

# Entity Table Functions 
def delete_rows():
    """
    Clears all rows in the table.
    This will remove all dynamically added labels and entries.
    """
    global rows, table_frame

    # Loop through each row in the rows list and remove the widgets from the grid
    for label0, label1, label2, entry, add_button in rows:
        label0.grid_forget()
        label1.grid_forget()  # Remove the first label
        label2.grid_forget()  # Remove the second label
        entry.grid_forget()   # Remove the entry widget
        add_button.grid_forget() # Remove the save button 

    # Clear the rows list
    rows.clear()

    # Update the table to reflect the changes
    table_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))

def add_row(ent_type, value1="Static 1", value2="Static 2", editable_value=""):
    global table_frame, canvas
    row_index = len(rows) + 1  # New row index

    

    case_entities_list.update({
    "type": ent_type,
    "ent": value1
    })

    label0 = ctk.CTkLabel(table_frame, text=ent_type)
    label0.grid(row=row_index, column=0, padx=10, pady=5)
   

    label1 = ctk.CTkLabel(table_frame, text=value1)
    label1.grid(row=row_index, column=1, padx=10, pady=5)
    
    label2 = ctk.CTkLabel(table_frame, text=value2)
    label2.grid(row=row_index, column=2, padx=10, pady=5)
    
    entry = ctk.CTkEntry(table_frame, width=270)
    entry.grid(row=row_index, column=3, padx=10, pady=5)
    entry.insert(0, editable_value)

    add_button = ctk.CTkButton(table_frame, text="Save Note", command=lambda: save_or_clear_note(entry, row_index, value1), 
                                width=40, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_button.grid(row=row_index, column=4, padx=5, sticky="w")


    check_and_insert_notes(value1, entry)
    track_entry_changes(entry, row_index)


    rows.append((label0, label1, label2, entry, add_button))
    table_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))

def check_and_insert_notes(entity, entry):
    # Path to your CSV file
    csv_file = 'settings/entity_notes.csv'
    
    # Initialize a variable to store the note if found
    note = ""
    
    # Open the CSV file and check if the entity has any notes
    try:
        with open(csv_file, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            # Skip the header row if there's one
            next(reader)
            
            for row in reader:
                if row[0] == entity:  # Check if the entity matches
                    note = row[1]  # Assuming the note is in the second column
                    break
        
        # If a note was found, insert it into the entry
        if note:
            log_debug_action(entity)
            highlight_entity_in_text(entity)
            entry.delete(0, "end")  # Clear any existing text in the entry
            entry.insert(0, note)   # Insert the note into the entry
            
    except FileNotFoundError:
        log_debug_action(f"Error: The file '{csv_file}' was not found.")
    except Exception as e:
        log_debug_action(f"An error occurred: {e}")

original_notes = {}

def highlight_entity_in_text(search_text):
    log_debug_action(search_text)
    if not search_text.strip():

        return  # Don't search for empty strings
    
    start = "1.0"

    while True:
        start = note_area.search(search_text, start, stopindex="end", nocase=True)
        if not start:
            break  # Exit loop if no more matches
        
        end = f"{start}+{len(search_text)}c"  # Calculate end position
        note_area.tag_add("highlight", start, end)  # Apply tag
        
        start = end  # Move start position to continue searching
    
    note_area.tag_config("highlight", foreground="black", background="lightgreen")  # Style the highlight

def track_entry_changes(entry, row_index):
    """
    Track the initial note value for each entry when first loaded or checked.
    """
    global original_notes
    original_notes[row_index] = entry.get()  # Store the initial value of the entry for that row

def save_or_clear_note(entry, row_index, entity):
    """
    Checks if the entry note has changed, then saves or clears the note accordingly.
    """
    global original_notes
    current_note = entry.get()  # Get the current value of the entry

    # Check if the note has changed from the original note for the specific row
    if current_note != original_notes.get(row_index, ""):
        if current_note == "":  # If the entry is cleared
            log_debug_action(f"Note for {entity} was cleared.")
            update_note_in_csv(entity, "")  # Clear the note in the CSV (empty note)
        else:
            log_debug_action(f"Note for {entity} was changed.")
            update_note_in_csv(entity, current_note)  # Save the new context to the CSV
        
        # Update the original note for that row
        original_notes[row_index] = current_note
    else:
        log_debug_action(f"No change detected for {entity}.")

def update_note_in_csv(entity, new_note):
    """
    Update the note for a specific entity in the CSV file.
    If the entity exists, update the note. If not, add the entity.
    """
    rows = []
    updated = False
    csv_file = 'settings/entity_notes.csv'
    
    # Read the existing CSV file and update the note for the given entity
    try:
        with open(csv_file, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            header = next(reader)  # Skip header row
            rows.append(header)  # Add header back to rows

            # Loop through the rows and find the entity to update
            for row in reader:
                if row[0] == entity:
                    row[1] = new_note  # Update the note for the entity
                    updated = True
                rows.append(row)
    
    except FileNotFoundError:
        log_debug_action(f"Error: The file '{csv_file}' was not found.")
        return
    
    # If the entity wasn't found and a note exists, add the new entity
    if not updated and new_note:
        rows.append([entity, new_note])
    
    # Write the updated rows back to the CSV file
    try:
        with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerows(rows)
            log_debug_action(f"CSV file '{csv_file}' updated successfully.")
    except Exception as e:
        log_debug_action(f"An error occurred while updating the CSV file: {e}")




def start_program(proc=0):
    global status_label, menu_bar, note_area, title_entry, tab_control, top_frame, cases_menu
    global root
    global note_font
    global dropdown_values, dropdown, corresponding_values

    root = ctk.CTk()
    log_debug_action(f"Start Program Function has started to build the GUI")

    root.title("Case Note Builder - Tool")
    root.geometry("800x600")
    root.update_idletasks()
    root.configure(bg="#1e1e2f")
    settings = read_settings("config.csv")
    initial_font_size = int(settings.get("font_size"))
    bold_font = font.Font(family="Verdana", weight="bold", size=10)
    note_font = ctk.CTkFont(family='Verdana', size=initial_font_size)

    # Create the top menu bar using standard Tkinter Menu
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)

    # File Menu
    file_menu = tk.Menu(menu_bar)
    menu_bar.add_cascade(label="File", menu=file_menu)
    #file_menu.add_command(label="New", command=lambda: print("New File"))
    #file_menu.add_command(label="Open", command=lambda: print("Open File"))
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)
    
    # Options Menu
    cases_menu = tk.Menu(menu_bar)
    menu_bar.add_cascade(label="My Cases", menu=cases_menu)

    # My Cases Menu
    options_menu = tk.Menu(menu_bar)
    menu_bar.add_cascade(label="Options", menu=options_menu)
    options_menu.add_command(label="Settings", command=lambda: open_settings_menu(root))

    # SOC Tools Menu
    soc_tools_menu = tk.Menu(menu_bar)
    menu_bar.add_cascade(label="SOC Tools", menu=soc_tools_menu)
    load_plugins(soc_tools_menu)

    entities_menu = tk.Menu(menu_bar)
    menu_bar.add_cascade(label="Case Entities", menu=entities_menu)
    entities_menu.add_command(label="Add Entitiy", command=entitity_manager_window)


    from core_functions.about import open_about_window
    help_menu = tk.Menu(menu_bar)
    menu_bar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="About", command=open_about_window)
    help_menu.add_command(label="Bug Report", command=core_functions.miscFuncs.bug_report)
    help_menu.add_command(label="Github", command=core_functions.miscFuncs.open_github)
    help_menu.add_command(label="Help Docs", command=core_functions.miscFuncs.open_help)
    help_menu.add_command(label="Message the Devs", command=core_functions.miscFuncs.msg_dev)
    help_menu.add_command(label="Submit Idea", command=core_functions.miscFuncs.submit_idea)


    # Frame for the status and timer
    top_frame = ctk.CTkFrame(root, fg_color="#333333")
    top_frame.pack(fill=tk.X)
    
    # Status label
    status_label = ctk.CTkLabel(top_frame, text="Welcome!", font=("Helvetica", 10, "bold"), anchor="w")
    status_label.pack(side=tk.LEFT, fill=tk.X, padx=22, pady=2)  # Fill horizontally, with padding

    # Configure grid weight to ensure proper resizing
    root.grid_rowconfigure(0, weight=1)  # Make row 0 expand vertically
    root.grid_columnconfigure(0, weight=1)  # Ensure column expands horizontally if needed


    # Create a container frame to hold both the left and right frames (70/30 split)
    container_frame = ctk.CTkFrame(root)
    container_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

    # Left pane (Note area)
    left_frame = ctk.CTkFrame(container_frame, fg_color="#2d2d44")
    left_frame.grid(row=0, rowspan=100, column=0, sticky="nsew", padx=2, pady=2)

    # Title entry field at the top of the note area
    title_entry = ctk.CTkEntry(left_frame, placeholder_text="Enter case title", font=("Verdana", 12), width=200)
    title_entry.pack(padx=5, pady=5, fill=tk.X)

    # Create a frame to hold the textbox and scrollbar
    text_frame = ctk.CTkFrame(left_frame, fg_color="#1e1e2f")
    text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Add a Textbox
    note_area = ctk.CTkTextbox(text_frame, height=750, wrap=tk.WORD, fg_color="#2d2d44", text_color="#ffffff", font=note_font)
    note_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)


    # Right pane (Input fields and tabs)
    right_frame = ctk.CTkFrame(container_frame, width=100, fg_color="#1e1e2f")
    right_frame.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)
    right_frame.grid_propagate(False)
    



    container_frame.grid_columnconfigure(0, weight=50)  # Left pane takes 70%
    container_frame.grid_columnconfigure(1, weight=2, minsize=100)  # Right pane takes 30%

    # Tab control for the right pane
    tab_control = ctk.CTkTabview(right_frame)
    tab_control.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    global user_entry, role_entry, email_entry, topvalue, host_entry, ip_entry, hash_entry
    # General Tab
    general_tab = tab_control.add("General")
    user_label = ctk.CTkLabel(general_tab, text="User:")
    user_label.grid(row=0, column=0, padx=2, pady=2, sticky="w")
    user_entry = ctk.CTkEntry(general_tab, placeholder_text="Enter user", width=200)
    user_entry.grid(row=0, column=1, padx=2, pady=2, sticky="w")

    role_label = ctk.CTkLabel(general_tab, text="Role:")
    role_label.grid(row=1, column=0, padx=2, pady=2, sticky="w")
    role_entry = ctk.CTkEntry(general_tab, placeholder_text="Enter role", width=200)
    role_entry.grid(row=1, column=1, padx=2, pady=2, sticky="w")

    email_label = ctk.CTkLabel(general_tab, text="Email:")
    email_label.grid(row=2, column=0, padx=2, pady=2, sticky="w")
    email_entry = ctk.CTkEntry(general_tab, placeholder_text="Enter email", width=200)
    email_entry.grid(row=2, column=1, padx=2, pady=2, sticky="w")

    checkbox_var = ctk.BooleanVar(value=True)  # Set to True to make it checked by default
    tick_label = ctk.CTkLabel(general_tab, text="Add to top:")
    tick_label.grid(row=3, column=0, padx=2, pady=2, sticky="w")
    topvalue = ctk.CTkCheckBox(general_tab, text="", onvalue=True, offvalue=False, variable=checkbox_var)
    topvalue.grid(row=3, column=1, pady=2, sticky="w")
    add_button = ctk.CTkButton(general_tab, text="Add User", command=add_user, 
                                width=40, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_button.grid(row=4, column=1,padx=(0,20), pady=(0, 10), sticky="ew")

    host_label = ctk.CTkLabel(general_tab, text="Host:")
    host_label.grid(row=5, column=0, padx=2, pady=2, sticky="w")
    host_entry = ctk.CTkEntry(general_tab, placeholder_text="Enter host", width=200)
    host_entry.grid(row=5, column=1, padx=2, pady=2, sticky="w")
    add_button = ctk.CTkButton(general_tab, text="Add Host", command=add_host, 
                                width=40, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_button.grid(row=6, column=1, padx=(0,20), pady=(0, 10), sticky="ew")

    ip_label = ctk.CTkLabel(general_tab, text="IP Address:")
    ip_label.grid(row=7, column=0, padx=2, pady=2, sticky="w")
    ip_entry = ctk.CTkEntry(general_tab, placeholder_text="Enter IP address", width=200)
    ip_entry.grid(row=7, column=1, padx=2, pady=2, sticky="w")
    add_button = ctk.CTkButton(general_tab, text="Scan IP", command=scan_ip, 
                                width=40, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_button.grid(row=8, column=1,padx=(0,20), pady=(0, 10), sticky="ew")

    hash_label = ctk.CTkLabel(general_tab, text="File Hash:")
    hash_label.grid(row=9, column=0, padx=2, pady=2, sticky="w")
    hash_entry = ctk.CTkEntry(general_tab, placeholder_text="Enter File Hash", width=200)
    hash_entry.grid(row=9, column=1, padx=2, pady=2, sticky="w")
    add_button = ctk.CTkButton(general_tab, text="Scan Hash", command=scan_hash, 
                                width=40, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_button.grid(row=10, column=1,padx=(0,20), pady=(0, 10), sticky="ew")

    # Outcome Label
    label = ctk.CTkLabel(general_tab, text="Outcome:", font=("Arial", 14, "bold"), fg_color="transparent", text_color="#ffffff")
    label.grid(row=12, column=0, padx=10, pady=5, sticky="w")

    # Dropdown (Combobox)
    dropdown_values, corresponding_values = load_csv_data()

    dropdown = ctk.CTkComboBox(general_tab, values=dropdown_values, width=200)
    dropdown.grid(row=12, column=1, padx=10, pady=5, sticky="w")

    # Insert Button
    add_button = ctk.CTkButton(general_tab, text="Insert Outcome", command=insert_corresponding_value, 
                            width=40, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_button.grid(row=13, column=1,padx=(0,20), pady=(0, 10), sticky="ew")


   
    # Email Tab
    email_tab = tab_control.add("Email")
    global emailSender, emailRecipient, emailSubject, emailAttachments
    # Email Sender
    email_sender_label = ctk.CTkLabel(email_tab, text="Sender:", font=("Verdana", 12), text_color="#ffffff")
    email_sender_label.grid(row=0, column=0, padx=2, pady=2, sticky="w")
    emailSender = ctk.CTkEntry(email_tab, placeholder_text="Enter Email Sender", width=200)
    emailSender.grid(row=0, column=1, padx=2, pady=2, sticky="w")
    add_sender_button = ctk.CTkButton(email_tab,command=lambda: add_info("sender", emailSender), text="Add Info", width=20, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_sender_button.grid(row=1, column=1, padx=(0,20), pady=(0, 10), sticky="ew")

    # Email Recipient
    email_recipient_label = ctk.CTkLabel(email_tab, text="Recipient:", font=("Verdana", 12), text_color="#ffffff")
    email_recipient_label.grid(row=2, column=0, padx=2, pady=2, sticky="w")
    emailRecipient = ctk.CTkEntry(email_tab, placeholder_text="Enter Email Recipient", width=200)
    emailRecipient.grid(row=2, column=1, padx=2, pady=2, sticky="w")
    add_recipient_button = ctk.CTkButton(email_tab,command=lambda: add_info("recipient", emailRecipient), text="Add Info", width=20, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_recipient_button.grid(row=3, column=1,padx=(0,20), pady=(0, 10), sticky="ew")

    # Email Subject
    email_subject_label = ctk.CTkLabel(email_tab, text="Subject:", font=("Verdana", 12), text_color="#ffffff")
    email_subject_label.grid(row=4, column=0, padx=2, pady=2, sticky="w")
    emailSubject = ctk.CTkEntry(email_tab, placeholder_text="Enter Email Subject", width=200)
    emailSubject.grid(row=4, column=1, padx=2, pady=2, sticky="w")
    add_subject_button = ctk.CTkButton(email_tab, command=lambda: add_info("subject", emailSubject), text="Add Info", width=20, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_subject_button.grid(row=5, column=1,padx=(0,20), pady=(5, 10), sticky="ew")

    # Email Attachments
    email_attachments_label = ctk.CTkLabel(email_tab, text="Attachments:", font=("Verdana", 12))
    email_attachments_label.grid(row=6, column=0, padx=2, pady=2, sticky="w")
    emailAttachments = ctk.CTkEntry(email_tab,placeholder_text="Enter Email Attachments", width=200)
    emailAttachments.grid(row=6, column=1, padx=2, pady=2, sticky="w")
    add_attachments_button = ctk.CTkButton(email_tab, command=lambda: add_info("attachments", emailAttachments), text="Add Info", width=20, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    add_attachments_button.grid(row=7, column=1,padx=(0,20), pady=(5, 10), sticky="w")

    # Search Tab
    global search_entry, results_list
    search_tab = tab_control.add("Search")
    search_label = ctk.CTkLabel(search_tab, text="Enter search term:", font=("Verdana", 12, "bold"), text_color="#ffffff")
    search_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

    # Search Entry
    search_entry = ctk.CTkEntry(search_tab, width=250)
    search_entry.grid(row=1, column=0, padx=10, pady=5, sticky="w")
    search_entry.bind("<Return>", search_files)

    # Search Button
    search_button = ctk.CTkButton(search_tab, text="Search", command=search_files, width=20, height=15, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    search_button.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

    # Results Listbox
    
    results_list = tk.Listbox(search_tab, width=40, height=15, bg="#2d2d44", fg="#ffffff", font=("Arial", 12), selectbackground="#4C9CD7", selectforeground="#ffffff")
    results_list.grid(row=3, column=0, padx=10, pady=20)
    results_list.bind("<Double-1>", open_file)


    global rows, table_frame, canvas
    rows = []

    # Create canvas and scrollbar for scrollable area
    canvas = tk.Canvas(search_tab, height=300, bg="#2d2d44",)
    scrollbar = tk.Scrollbar(search_tab, orient="vertical", command=canvas.yview)
    scrollbarX = tk.Scrollbar(search_tab, orient="horizontal", command=canvas.xview)
    
    scrollbar.config(background="#4D4D4D", relief="flat")
    scrollbarX.config(background="#4D4D4D", relief="flat")

    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.configure(xscrollcommand=scrollbarX.set, xscrollincrement=10)

    table_frame = ctk.CTkFrame(canvas)
    table_frame.grid(row=30, column=0, columnspan=10, pady=10, padx=10, sticky="w")
    table_frame.grid_columnconfigure(2, weight=1, minsize=150, uniform="entry_width")

    # Create the window inside the canvas for the table
    canvas.create_window((0, 0), window=table_frame, anchor="nw")

    # Grid canvas and scrollbar
    canvas.grid(row=30, column=0, columnspan=3, pady=10, padx=1)
    scrollbar.grid(row=30, column=2, sticky="nse")
    scrollbarX.grid(row=30, column=0, columnspan=3, sticky="ewn")

    # Table headers
    headers = ["Type","Entity", "Observed", "Note", "Action"]
    for col, text in enumerate(headers):
        label = ctk.CTkLabel(table_frame, text=text, font=("Arial", 14, "bold"))
        label.grid(row=0, column=col, padx=20, pady=5, sticky="w")

    table_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))

     #Example: Create a 2x2 grid for buttons at the bottom of the right frame
    button_1 = ctk.CTkButton(general_tab, text="Save Case as", width=100, command=lambda: save_note(2), height=20, fg_color="#4C9CD7", hover_color="#368BB7", font=("Verdana", 12, "bold"))
    button_2 = ctk.CTkButton(general_tab, text="Next Case", width=100, command=next_case, height=20, fg_color="#4CAF50", hover_color="#45A049", font=("Verdana", 12, "bold"))
    button_3 = ctk.CTkButton(general_tab, text="Copy All", width=100, command=copy_to_clipboard, height=20, fg_color="#166534", hover_color="#22c55e", font=("Verdana", 12, "bold"))
    button_4 = ctk.CTkButton(general_tab, text="Clear", width=100, command=clear_input, height=20, fg_color="#F44336", hover_color="#D32F2F", font=("Verdana", 12, "bold"))

    button_url = ctk.CTkButton(general_tab, text="Sanatize URLs", width=100, command=lambda: core_functions.miscFuncs.sanitize_urls(note_area), height=20, fg_color="#d97706", hover_color="#f59e0b", font=("Verdana", 12, "bold"))
    button_url.grid(row=20, column=0, padx=2, pady=2, sticky="ew")  # Top-left button

    # Add buttons to a 2x2 grid layout at the bottom of the right frame
    button_1.grid(row=22, column=0, padx=2, pady=2, sticky="ew")  # Top-left button
    button_2.grid(row=22, column=1, padx=2, pady=2, sticky="ew")  # Top-right button
    button_3.grid(row=21, column=1, padx=2, pady=2, sticky="ew")  # Bottom-left button
    button_4.grid(row=21, column=0, padx=2, pady=2, sticky="ew")  # Bottom-right button


    for tab in [general_tab, email_tab, search_tab]:
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)
    log_debug_action(f"GUI loaded")


    compare_versions(1)
    populate_cases_menu()
    root.after(3000, check_spelling)

    update_status_message("All Modules Loaded!")
    root.mainloop()




if __name__ == "__main__":
    global settings
    csv_file = "config.csv"

    settings = read_settings(csv_file)
    log_debug_action("- - - - - - - - - - - - - - - - - - - -")
    log_debug_action("Program Started")
    log_debug_action(f"Config file set as {csv_file}")

    start_program()



#   log_debug_action(f"")

