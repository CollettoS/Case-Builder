import      tkinter         as          tk
from        tkinter         import      messagebox, ttk, font, filedialog, Menu
import      requests
import      os
import      random
from        datetime        import      datetime
import      csv
from        spellchecker    import      SpellChecker
import      webbrowser
import      pycountry
import      re
import      json


FOLDER_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'saved_notes')

spell = SpellChecker()

def get_country_name(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country.name if country else "Unknown"
    except KeyError:
        return "Unknown"

def search_files(type=1, search="None"):
    if type == 1:
        search_term = search_entry.get()  # Get the search term from the search bar
    elif type == 2:
        search_term = search

    if not os.path.isdir(FOLDER_PATH):
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
        if matching_files:
            update_status_message(f"{search_term}: observed before!","flash")
# Function to open the file when a result is clicked
def open_file(event):
    # Get the selected file name
    try:
        selected_file = results_list.get(results_list.curselection())
        if selected_file:
            # Find the full path of the selected file
            file_path = None
            for root, dirs, files in os.walk(FOLDER_PATH):
                for file in files:
                    if file == selected_file:
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
            else:
                messagebox.showerror("Error", "File not found.")
        else:
            messagebox.showerror("Error", "No file selected.")
    except IndexError:
        messagebox.showerror("Error", "Please select a file.")
# Function to open a file and insert its content into the text area
def open_file_from_saved():
    # Open file dialog to select a .txt file
    file_path = filedialog.askopenfilename(
        title="Open Text File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "r") as file:
                content = file.read()
            # Clear the text area and insert the file content
            note_area.delete(1.0, tk.END)
            note_area.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {e}")

def load_csv_data(filename):
    # Read the CSV and return two lists: one for dropdown values and one for corresponding values to insert
    dropdown_values = []
    corresponding_values = []
    update_status_message("Reading CSV...","info ")

    with open(filename, newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            # Check if the first column contains '1'
            if row[0] == '1':
                dropdown_values.append(row[1])  # First column for the dropdown (this would be '1' in this case)
                corresponding_values.append(row[2])  # Second column for the value to insert
                update_status_message("CSV Read...","info")
    return dropdown_values, corresponding_values

def read_settings(csv_file):
    settings = {}
    with open(csv_file, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            settings[row['setting_name']] = row['setting_value']
    return settings

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

def on_entry_click(event, entry, placeholder_text):
    """Clear the placeholder text when the user clicks into the entry box."""
    if entry.get() == placeholder_text:
        entry.delete(0, tk.END)  # Clear the placeholder text

def on_focusout(event, entry, placeholder_text):
    """Reinsert the placeholder text if the entry is left empty."""
    if entry.get() == "":
        entry.insert(0, placeholder_text)

def insert_text(formatted_text, position="default"):
    if position == "top":
        note_area.insert("1.0", formatted_text + "\n")
    elif position == "end":
        note_area.insert(tk.END, formatted_text + "\n")
    else:
        note_area.insert(tk.END, formatted_text + "\n")

def scan_ip():
    ip = ip_entry.get().strip()
    if not ip:
        update_status_message("Error: Please enter a valid IP","error")
        ip_entry.delete(0, tk.END)

        return

    try:
        api1 = str(settings.get("abuseipdb_api")).strip()
        print(api1)
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
        search_files(2, ip)
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
        ip_entry.delete(0, tk.END)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to scan IP: {e}")

def scan_hash():
    file_hash = hash_entry.get().strip()
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

        search_files(2, file_hash)

        # If malicious, display details
        if malicious_found:
            formatted_text += "\nMalicious Detections:\n"
            formatted_text += malicious_details.strip()  # Strip trailing newline
        else:
            formatted_text += "\nNo Malicious Detections\n"
        
        formatted_text += "\n"
        insert_text(formatted_text)
        hash_entry.delete(0, tk.END)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to scan file hash: {e}")

def add_user():
    user = user_entry.get()
    role = role_entry.get()
    email = email_entry.get()
    topText = topvalue.get()
    print(topText)
    if user == "Enter user":
        user = ""
    if role == "Enter role":
        role = ""
    if email == "Enter email":
        email = ""
    user_text = ""
    if user:
        user_text += f"\nUser:\t\t\t{user}"
        search_files(2, user)

        line = 1
    if role:
        user_text += f"\nRole:\t\t\t{role}"
        if user:
            line = 1
        else: 
            line = 2
    if email:
        user_text += f"\nEmail:\t\t\t{email}"
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
            insert_text(user_text, position="top")
        else:
            insert_text(user_text)
        user_entry.delete(0, tk.END)
        role_entry.delete(0, tk.END)
        email_entry.delete(0, tk.END)
        event = "<FocusOut>"
        on_focusout(event, user_entry, user_placeholder)
        on_focusout(event, role_entry, role_placeholder)
        on_focusout(event, email_entry, email_placeholder)

def add_host():
    host = host_entry.get()
    host_text = f"Host:\t\t\t{host}\n"
    insert_text(host_text)
    host_entry.delete(0, tk.END)

def add_info(info_type, entry_widget):
    info_value = entry_widget.get()
    if info_value:
        search_files(2, info_value)
        if info_type:
            match info_type:
                case "sender":
                    sender_text = f"Sender:\t\t\t{info_value}\n"
                    insert_text(sender_text)
                    load_email_tab(1)  # Clear email sender field
                case "recipient":
                    recipient_text = f"Recipient:\t\t\t{info_value}\n"
                    insert_text(recipient_text)
                    load_email_tab(2)  # Clear email recipient field
                case "subject":
                    subject_text = f"Subject:\t\t\t{info_value}\n"
                    insert_text(subject_text)
                    load_email_tab(3)  # Clear email subject field
                case "attachments":
                    attachments_text = f"Attachments:\t\t\t{info_value}\n"
                    insert_text(attachments_text)
                    load_email_tab(4)  # Clear email attachments field
                case _:
                    update_status_message("Error: Info type unknown", "error")

def apply_dark_theme(widget, color="none"):
    if color == "none":
        widget.configure(bg="#2d2d44", fg="#ffffff", insertbackground="#ffffff")
    else: 
        widget.configure(bg=color, fg="#ffffff", insertbackground="#ffffff")

def next_case():
    saved = save_note(1)
    if saved:
        clear_input()
        update_status_message(f"Note area cleared! - File saved as: {saved}","success")

def clear_input():
    note_area.delete(1.0, tk.END)
    case_entry.delete(0, tk.END)
    update_status_message("Note area cleared!","warning")

def is_case_open(folder_path, file_name):
    file_path = os.path.join(folder_path, file_name)
    return os.path.isfile(file_path)

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
    note_content = note_area.get("1.0", tk.END).strip()  # Grab all text from the area, excluding any trailing newlines
    case_name = case_entry.get().strip() # Get case name (e.g. MALWARE DETECTED BLA BLA)

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

def copy_to_clipboard():
    # Get the content of the Text widget
    text_content = note_area.get("1.0", tk.END)  # Start from "1.0" (first character) to the end
    root.clipboard_clear()  # Clear the clipboard before adding new content
    root.clipboard_append(text_content)  # Append the content to the clipboard
    root.update()
    update_status_message("Content copied to clipboard!","success")
    note_area.config(bg="#9ae6a6")
    note_area.after(500, lambda: note_area.config(bg="#2d2d44"))

def flash_status(message, duration=5000):  # Duration in milliseconds
    # Flash the status message between red and orange for a specified duration
    def toggle_flash(counter=0):
        if counter < duration / 500:  # Duration divided by 500ms toggle interval
            current_color = status_label.cget("bg")
            if current_color == "#f44336":  # Red
                status_label.config(bg="#ff9800")  # Orange
                top_frame.config(bg="#ff9800")

            else:
                status_label.config(bg="#f44336")  # Red
                top_frame.config(bg="#f44336")

            status_label.after(500, toggle_flash, counter + 1)  # Increment counter

        else:
            # Stop flashing by setting a final color (optional)
            status_label.config(bg="#ff9800")
            top_frame.config(bg="#ff9800")


    status_label.config(text=message, fg="#ffffff")  # Set the message text
    toggle_flash()  # Start flashing

def update_status_message(message, message_type="info"):
    if message_type == "success":
        status_label.config(text=message, bg="#4CAF50", fg="#ffffff")  # Green for success
        top_frame.config(bg="#4CAF50")
    elif message_type == "error":
        status_label.config(text=message, bg="#f44336", fg="#ffffff")  # Red for error
        top_frame.config(bg="#f44336")
    elif message_type == "warning":
        status_label.config(text=message, bg="#ff9800", fg="#ffffff")  # Orange for warning
        top_frame.config(bg="#ff9800")
    elif message_type == "flash":
        flash_status(message)  # Flash effect for "flash"
    else:
        status_label.config(text=message, bg="#333333", fg="#ffffff")  # Default color for info

def about():
    messagebox.showinfo("About", "Case Builder\n\nThis tool is designed to help case notes easier and nore uniform\n\nDeveloped by: \t\t\tSam Collett \nTester and contributor: \t\tRyan Ferns\n\n\n If you find any bugs or have a suggestion, message Sam")

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

def open_settings_menu(root, proc=0):
    if proc == 1:
        pass
    else:
        csv_file = 'config.csv'
        read_settings(csv_file)
        # Create a settings window
        settings_window = tk.Toplevel(root)
        settings_window.title("Settings")
        settings_window.geometry("400x500")
        settings_window.configure(bg="#1e1e2f")

        # Create a Notebook (tab container)
        notebook = ttk.Notebook(settings_window)

        # Create tabs
        general_tab = ttk.Frame(notebook)
        appearance_tab = ttk.Frame(notebook)
        advanced_tab = ttk.Frame(notebook)

        # Add tabs to the notebook
        notebook.add(general_tab, text="General")
        notebook.add(appearance_tab, text="Appearance")
        notebook.add(advanced_tab, text="Advanced")
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # ---- General Tab ----
        tk.Label(general_tab, text="General Settings", font=("Arial", 14), bg="#1e1e2f", fg="white").pack(anchor="w", pady=5)

        tk.Label(general_tab, text="Enable Features:", bg="#1e1e2f", fg="white").pack(anchor="w", pady=(10, 5))

        def get_t_or_f(a, setting_value):
            value = a.get(setting_value)
            if value == "True":
                 return tk.BooleanVar(value=True)
            if value == "False":
                return tk.BooleanVar(value=False)
            
        spell_check_value   = get_t_or_f(settings, "spell_check")
        timer_value         = get_t_or_f(settings, "enable_timer")
        email_tab_value     = get_t_or_f(settings, "enable_email_tab")

        tk.Checkbutton(general_tab, text="Spell Checker", variable=spell_check_value, bg="#1e1e2f", fg="white", selectcolor="#3a3a5c").pack(anchor="w")
        tk.Checkbutton(general_tab, text="Timer", variable=timer_value, bg="#1e1e2f", fg="white", selectcolor="#3a3a5c").pack(anchor="w")
        tk.Checkbutton(general_tab, text="Email Tab", variable=email_tab_value, bg="#1e1e2f", fg="white", selectcolor="#3a3a5c").pack(anchor="w")

        # ---- Appearance Tab ----
        tk.Label(appearance_tab, text="Appearance Settings", font=("Arial", 14), bg="#1e1e2f", fg="white").pack(anchor="w", pady=5)
        tk.Label(appearance_tab, text="Theme: (THIS DOES NOT WORK!)", bg="#1e1e2f", fg="white").pack(anchor="w")
        theme_var = tk.StringVar(value="Dark")
        theme_dropdown = ttk.Combobox(appearance_tab, textvariable=theme_var, values=["Dark", "Light", "System Default"], state="readonly", width=25)
        theme_dropdown.pack(anchor="w", pady=5)
        tk.Label(appearance_tab, text="I have not finished this as half way through I asked myself,", font=("Arial", 8), bg="#1e1e2f", fg="white").pack(anchor="w", pady=2)
        tk.Label(appearance_tab, text="who would actually use Light theme?", font=("Arial", 8), bg="#1e1e2f", fg="white").pack(anchor="w", pady=1)

        font_size_var = tk.StringVar(value=str(settings.get("font_size")))  # Use StringVar to bind the value
        tk.Label(appearance_tab, text="Font Size:", bg="#1e1e2f", fg="white").pack(anchor="w")
        font_size_spinbox = tk.Spinbox(appearance_tab, textvariable=font_size_var, from_=8, to=48, width=5)
        font_size_spinbox.pack(anchor="w", pady=5)

        # ---- Advanced Tab ----
        api1_var = tk.StringVar(value=str(settings.get("abuseipdb_api")))
        api2_var = tk.StringVar(value=str(settings.get("vt_api")))

        tk.Label(advanced_tab, text="Advanced Settings", font=("Arial", 14), bg="#1e1e2f", fg="white").pack(anchor="w", pady=5)
        tk.Label(advanced_tab, text="AbuseIPDB API Key:", bg="#1e1e2f", fg="white").pack(anchor="w")
        api1 = tk.Entry(advanced_tab, textvariable=api1_var, width=50)
        api1.pack(anchor="w", pady=5)
        tk.Label(advanced_tab, text="VirusTotal API Key:", bg="#1e1e2f", fg="white").pack(anchor="w")
        api2 = tk.Entry(advanced_tab,textvariable=api2_var, width=50)
        api2.pack(anchor="w", pady=5)


        tk.Label(advanced_tab, text="Enable Debugging:", bg="#1e1e2f", fg="white").pack(anchor="w", pady=(10, 5))
        debug_var = tk.BooleanVar()
        tk.Checkbutton(advanced_tab, text="Debug Mode", variable=debug_var, bg="#1e1e2f", fg="white", selectcolor="#3a3a5c").pack(anchor="w")

        # Save and Close Buttons
        tk.Button(settings_window, text="Save", bg="#3a3a5c", fg="white", command=lambda: save_settings(theme_var, spell_check_value, debug_var, font_size_var, api1_var, api2_var, timer_value, email_tab_value)).pack(side="right", padx=10, pady=10)
        tk.Button(settings_window, text="Close", bg="#3a3a5c", fg="white", command=settings_window.destroy).pack(side="right", padx=10, pady=10)

def save_settings(theme_var, spell_check_var, debug_var, font_size_var, api1, api2, timer_value, email_tab_value):
    csv_file = 'config.csv'
    # Retrieve the settings from input fields and variables
    theme = theme_var.get()
    sc_enabled = spell_check_var.get()    
    debug_enabled = debug_var.get()
    font_size = font_size_var.get()
    api1 = api1.get()
    api2 = api2.get()
    timer_value = timer_value.get()
    email_tab_value = email_tab_value.get()
    # Print the settings to verify (replace this with saving to a file or applying settings)
    # config.settings[""]
    # Update the settings dictionary and write to CSV
    settings["spell_check"] = str(sc_enabled)  # Convert boolean to string for CSV
    settings["enable_timer"] = str(timer_value)  # Convert boolean to string for CSV
    settings["enable_email_tab"] = str(email_tab_value)
    settings["debug_mode"] = str(debug_enabled)
    settings["theme"] = theme
    settings["font_size"] = str(font_size)
    settings["abuseipdb_api"] = str(api1)
    settings["vt_api"] = str(api2)

    # Save updated settings to the CSV
    new_font = int(font_size)
    write_settings(csv_file, settings)
    update_font_size(new_font)
    load_timer()
    load_email_top_tab()

def write_settings(csv_file, settings):
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["setting_name", "setting_value"])
        writer.writeheader()
        for setting_name, setting_value in settings.items():
            writer.writerow({"setting_name": setting_name, "setting_value": setting_value})
    read_settings("config.csv")

def update_font_size(new_size):
    new_size = int(new_size)  # Ensure it's an integer
    text_font.configure(size=new_size)  # Update the font size
    root.update_idletasks() 

def cut_text():
    note_area.event_generate("<<Cut>>")  # Use built-in Cut operation for Text widget

def copy_text():
    note_area.event_generate("<<Copy>>")  # Use built-in Copy operation for Text widget

def paste_text():
    note_area.event_generate("<<Paste>>")  # Use built-in Paste operation for Text widget

def undo_text(event=None):
    """Undo the last action in the text box."""
    note_area.edit_undo()

def redo_text(event=None):
    """Undo the last action in the text box."""
    note_area.edit_redo()
# Timer update function
def update_timer():
    global time_left, flash_timer
    if timer_running:
        if time_left > 0:
            minutes, seconds = divmod(time_left, 60)
            time_str = f"{minutes:02}:{seconds:02}"
            timer_label.config(text=time_str)
                        # Background color changes based on time remaining
            if time_left <= 10 * 60:  # Flash red at 10 minutes
                set_background("red")
            elif time_left <= 15 * 60:  # Change to red at 15 minutes
                set_background("orange")
            elif time_left <= 25 * 60:  # Change to orange at 20 minutes
                set_background("yellow")
            elif time_left <= 30 * 60:  # Change to yellow at 30 minutes
                set_background("#1e1e2f")
            else:
                reset_background()
            time_left -= 1
            root.after(1000, update_timer)  # Update every 1 second
        else:
            timer_label.config(text="00:00")
            start_button.config(text="Reset", state=tk.NORMAL)

def set_background(color):
    timer_label.config(bg=color)  # Change background color of the top frame

def reset_background():
    timer_label.config(bg="#1e1e2f")  # Reset to the default background color
# Start/Reset button function
def toggle_timer():
    global timer_running, time_left
    if timer_running:
        reset_timer()
        flash_timer = False
    else:
        start_timer()

def start_timer():
    global timer_running
    timer_running = True
    start_button.config(text="Reset", state=tk.NORMAL)
    update_timer()

def reset_timer():
    global timer_running, time_left, flash_timer
    flash_timer = False
    timer_running = False
    time_left = time_in_mins * 60  # Reset to 45 minutes
    timer_label.config(text="40:00")
    start_button.config(text="Start", state=tk.NORMAL)

def populate_cases_menu():
    global cases_menu  # Make it accessible globally

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
        messagebox.showerror("Error", f"Folder '{folder_path}' not found.")
        cases_menu.add_command(label="Folder not found", state=tk.DISABLED)
# Function to open a selected case
def open_case(file_name):
    change_case()
    file_path = os.path.join("open_cases", file_name)
    try:
        with open(file_path, "r") as f:
            content = f.read()
        note_area.delete(1.0, tk.END)
        case_entry.delete(0, tk.END)
        case_name = file_name.replace(".txt", "")

        note_area.insert(tk.END, content)
        case_entry.insert(tk.END, case_name)
    except Exception as e:
        messagebox.showerror("Error", f"Could not open {file_name}: {e}")

def change_case():
    content = note_area.get("1.0", tk.END).strip()

    if content:
        save_note(3)
    populate_cases_menu()
    
# - - - - - - - - - - - - - - - - - - - - -
#           GUI Elements 
# - - - - - - - - - - - - - - - - - - - - -

# Top memu bar 
def load_menubar(root):
    global cases_menu 

    # Create 'File' menu
    file_menu = tk.Menu(menu_bar, tearoff=0)
    file_menu.add_command(label="Save as", command=lambda: save_note(2))
    file_menu.add_command(label="Open Case", command=open_file_from_saved)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)
    # Create 'Help' menu
    help_menu = tk.Menu(menu_bar, tearoff=0)
    help_menu.add_command(label="About", command=about)
    # Create 'Options' menu
    options_menu = tk.Menu(menu_bar, tearoff=0)
    options_menu.add_command(label="Settings", command=lambda: open_settings_menu(root))
    # cases Menu
    cases_menu = tk.Menu(menu_bar, tearoff=0)
    cases_menu.add_separator()
    # Tools Menu
    tools_menu = tk.Menu(menu_bar, tearoff=0)


    menu_bar.add_cascade(label="File", menu=file_menu)
    menu_bar.add_cascade(label="My Cases", menu=cases_menu)
    menu_bar.add_cascade(label="SOC Tools", menu=tools_menu)
    menu_bar.add_cascade(label="Options", menu=options_menu)
    menu_bar.add_cascade(label="Help", menu=help_menu)
# Paned window - split, note area and tabs
def load_paned_windows():
    global input_frame, note_frame, paned_window
    # Create the PanedWindow
    paned_window = tk.PanedWindow(root, orient=tk.HORIZONTAL)
    paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # frame for the note area and the input box
    note_frame = tk.Frame(paned_window, bg="#1e1e2f")
    note_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Input frame inside note_frame
    input_frame = tk.Frame(note_frame, bg="#1e1e2f")
    input_frame.pack(fill=tk.X, padx=5, pady=5)
# Timer function
def load_timer():
    global timer_label, start_button
    timer_enabled = settings.get("enable_timer")
    if timer_enabled == "True":
        # Check if the timer elements already exist
        if 'timer_label' in globals() and timer_label.winfo_exists():
        # Timer is already created, so don't recreate it
            return
        # Timer label (Initially set to 45:00)
        timer_label = tk.Label(top_frame, text="40:00", font=("Helvetica", 20), bg="#1e1e2f", fg="#ffffff")
        timer_label.pack(side=tk.RIGHT, padx=10)

        # Timer button (Initially "Start")
        start_button = tk.Button(top_frame, text="Start", font=("Helvetica", 12), command=lambda: toggle_timer())
        start_button.pack(side=tk.RIGHT, padx=10)
    else:
        timer_label.destroy()
        start_button.destroy()
# Case name input area
def load_case_input():
    global case_entry
    # Label for the input box
    case_label = tk.Label(input_frame, text="Case:", font=("Helvetica", 12), bg="#1e1e2f", fg="white")
    case_label.pack(side=tk.LEFT, padx=5)

    # Input box for Case name
    case_entry = tk.Entry(input_frame, width=60, font=("Helvetica", 12))
    case_entry.pack(side=tk.LEFT, padx=5)
    apply_dark_theme(case_entry)

# - - Tab Pages - -

# General Tab
def load_general_tab():
    global dropdown, dropdown_values, ip_entry, hash_entry, corresponding_values, user_entry, role_entry, email_entry, topvalue, host_entry, general_tab
    # General tab
    style = ttk.Style()
    style.configure("TFrame", background="#1e1e2f")  # Set the background color for ttk.Frame

    # Apply the style to the general tab
    general_tab = ttk.Frame(tab_control, style="TFrame")
    tab_control.add(general_tab, text="General")

    # User input
    tk.Label(general_tab, text="User Info::",font=bold_font, bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
    # User input entry with placeholder
    user_entry = tk.Entry(general_tab, width=25)
    user_entry.insert(0, user_placeholder)
    apply_dark_theme(user_entry)
    user_entry.bind("<FocusIn>", lambda event: on_entry_click(event, user_entry, user_placeholder))
    user_entry.bind("<FocusOut>", lambda event: on_focusout(event, user_entry, user_placeholder))
    user_entry.pack(anchor="w")

    # Role input entry with placeholder
    role_entry = tk.Entry(general_tab, width=25)
    role_entry.insert(0, role_placeholder)
    apply_dark_theme(role_entry)
    role_entry.bind("<FocusIn>", lambda event: on_entry_click(event, role_entry, role_placeholder))
    role_entry.bind("<FocusOut>", lambda event: on_focusout(event, role_entry, role_placeholder))
    role_entry.pack(anchor="w")

    # Email input entry with placeholder
    email_entry = tk.Entry(general_tab, width=25)
    email_entry.insert(0, email_placeholder)
    apply_dark_theme(email_entry)
    email_entry.bind("<FocusIn>", lambda event: on_entry_click(event, email_entry, email_placeholder))
    email_entry.bind("<FocusOut>", lambda event: on_focusout(event, email_entry, email_placeholder))
    email_entry.pack(anchor="w")

    # Add user Button
    user_btn_frame = tk.Frame(general_tab, bg="#1e1e2f")
    user_btn_frame.pack(fill=tk.X, padx=5, pady=5)

    tk.Button(user_btn_frame, text="Add User",font=bold_font, command=add_user, bg="#3a3a5c", fg="#ffffff").pack(side=tk.LEFT,anchor="w", pady=5)
    user_entry.bind("<Return>", add_user)
    role_entry.bind("<Return>", add_user)
    email_entry.bind("<Return>", add_user)

    topvalue = tk.BooleanVar(value=True)
    add_to_top = tk.Checkbutton(user_btn_frame, text="Add to Top", variable=topvalue, 
                            bg="#1e1e2f", fg="white", font=("Helvetica", 10), 
                            selectcolor="#2d2d44")
    add_to_top.pack(side=tk.LEFT,pady=5)

    # Host Input
    tk.Label(general_tab, text="Host:",font=bold_font, bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
    host_entry = tk.Entry(general_tab, width=25)
    apply_dark_theme(host_entry)
    host_entry.pack(anchor="w")
    tk.Button(general_tab, text="Add Host",font=bold_font, command=add_host, bg="#3a3a5c", fg="#ffffff").pack(anchor="w", pady=5)
    host_entry.bind("<Return>", add_host)


    # IP Address input
    tk.Label(general_tab, text="IP Address:", font=bold_font, bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
    ip_entry = tk.Entry(general_tab, width=25)
    apply_dark_theme(ip_entry)
    ip_entry.pack(anchor="w")
    tk.Button(general_tab, text="Scan IP", font=bold_font,command=scan_ip, bg="#3a3a5c", fg="#ffffff").pack(anchor="w", pady=5)
    ip_entry.bind("<Return>", scan_ip)

    # Hash Input
    tk.Label(general_tab, text="File Hash:",font=bold_font,  bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
    hash_entry = tk.Entry(general_tab, width=25)
    apply_dark_theme(hash_entry)
    hash_entry.pack(anchor="w")
    tk.Button(general_tab, text="Check Hash",font=bold_font, command=scan_hash, bg="#3a3a5c", fg="#ffffff").pack(anchor="w", pady=5)
    hash_entry.bind("<Return>", scan_hash)

    dropdown_values, corresponding_values = load_csv_data(filename)


    # Outcome dropdown
    tk.Label(general_tab, text="Outcome:",font=bold_font,  bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
    dropdown = ttk.Combobox(general_tab, values=dropdown_values, width=25)
    dropdown.pack(anchor="w")
    tk.Button(general_tab, text="Insert",font=bold_font, command=insert_corresponding_value, bg="#3a3a5c", fg="#ffffff").pack(anchor="w", pady=5)
    addButtons(general_tab)
# Email Tab Title
def load_email_top_tab():
    global emailtab
    email_enabled = settings.get("enable_email_tab")
    if email_enabled == "True":
        if 'emailtab' in globals() and emailtab.winfo_exists():
            return

        emailtab = ttk.Frame(tab_control)
        tab_control.add(emailtab, text="Email")
        load_email_tab()
        addButtons(emailtab)
    else:
        try:
            emailtab.destroy()
        except:
            pass
# Search Tab
def load_search_tab():
    global search_entry, results_list
    # Search Tab
    searchtab = ttk.Frame(tab_control)
    tab_control.add(searchtab, text="Search")

    # Search bar input
    search_label = tk.Label(searchtab, text="Enter search term:",bg="#1e1e2f", fg="#ffffff")
    search_label.pack(padx=10, pady=5)

    search_entry = tk.Entry(searchtab, width=50, bg="#1e1e2f", fg="#ffffff")
    search_entry.pack(padx=10, pady=5)
    search_entry.bind("<Return>", search_files)

    # Search button
    search_button = tk.Button(searchtab, text="Search", command=search_files)
    search_button.pack(padx=10, pady=10)

    # Listbox to display results
    results_list = tk.Listbox(searchtab, width=50, height=15, bg="#2d2d44", fg="#ffffff",font=bold_font)
    results_list.config(bg="#2d2d44", font=("Arial", 12))
    results_list.pack(padx=10, pady=5)
    results_list.bind("<Double-1>", open_file)

    addButtons(searchtab)
# Email Tab
def load_email_tab(process=0):
    global emailSender, emailRecipient, emailSubject, emailAttachments

    if process:
        # Clear the specific email input field
        match process:
            case 1:
                emailSender.delete(0, tk.END)
            case 2:
                emailRecipient.delete(0, tk.END)
            case 3:
                emailSubject.delete(0, tk.END)
            case 4:
                emailAttachments.delete(0, tk.END)
            case _:
                update_status_message("Error: Email Process unknown", "error")
    else:

        # Email Sender Input
        tk.Label(emailtab, text="Email Sender:", font=bold_font, bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
        emailSender = tk.Entry(emailtab, width=25)
        apply_dark_theme(emailSender)
        emailSender.pack(anchor="w")
        tk.Button(emailtab, text="Add Info", font=bold_font, command=lambda: add_info("sender", emailSender), bg="#3a3a5c", fg="#ffffff").pack(anchor="w", pady=5)

        # Email Recipient
        tk.Label(emailtab, text="Email Recipient:", font=bold_font, bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
        emailRecipient = tk.Entry(emailtab, width=25)
        apply_dark_theme(emailRecipient)
        emailRecipient.pack(anchor="w")
        tk.Button(emailtab, text="Add Info", font=bold_font, command=lambda: add_info("recipient", emailRecipient), bg="#3a3a5c", fg="#ffffff").pack(anchor="w", pady=5)

        # Email Subject
        tk.Label(emailtab, text="Email Subject:", font=bold_font, bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
        emailSubject = tk.Entry(emailtab, width=25)
        apply_dark_theme(emailSubject)
        emailSubject.pack(anchor="w")
        tk.Button(emailtab, text="Add Info", font=bold_font, command=lambda: add_info("subject", emailSubject), bg="#3a3a5c", fg="#ffffff").pack(anchor="w", pady=5)

        # Email Attachments
        tk.Label(emailtab, text="Email Attachments:", font=bold_font, bg="#1e1e2f", fg="#ffffff").pack(anchor="w")
        emailAttachments = tk.Entry(emailtab, width=25)
        apply_dark_theme(emailAttachments)
        emailAttachments.pack(anchor="w")
        tk.Button(emailtab, text="Add Info", font=bold_font, command=lambda: add_info("attachments", emailAttachments), bg="#3a3a5c", fg="#ffffff").pack(anchor="w", pady=5)
        
        emailSender.bind("<Return>", lambda event: add_info("sender", emailSender))
        emailRecipient.bind("<Return>", lambda event: add_info("recipient", emailRecipient))
        emailSubject.bind("<Return>", lambda event: add_info("subject", emailSubject))
        emailAttachments.bind("<Return>", lambda event: add_info("attachments", emailAttachments))

# Other Tab
def load_other_tab():
    othertab = ttk.Frame(tab_control)
    tab_control.add(othertab, text="Other")



# - - Other - - 

# Right click menu
def show_context_menu(event):
    context_menu.tk_popup(event.x_root, event.y_root)  # Display the menu at the cursor position
# Add buttons to each tabs
def addButtons(loc):
    # Inline buttons at the bottom of the General tab 1
    button_frame2 = tk.Frame(loc, bg="#1e1e2f")
    button_frame2.pack(side=tk.BOTTOM, pady=2, fill=tk.X)

    btn3 = tk.Button(button_frame2, text="Save Case As",font=bold_font, command=lambda: save_note(2) ,bg="#fe75c8", fg="#000000", width=10)
    btn3.pack(side=tk.LEFT, padx=5, pady=5)

    btn4 = tk.Button(button_frame2, text="Next Case",font=bold_font, command=next_case, bg="#75fe7d", fg="#000000", width=10)
    btn4.pack(side=tk.LEFT, padx=5, pady=5)

    # Inline buttons at the bottom of the General tab 1
    button_frame = tk.Frame(loc, bg="#1e1e2f")
    button_frame.pack(side=tk.BOTTOM, pady=2, fill=tk.X)

    btn1 = tk.Button(button_frame, text="Copy",font=bold_font,command=copy_to_clipboard ,bg="#75feed", fg="#000000", width=10)
    btn1.pack(side=tk.LEFT, padx=5, pady=5)

    btn2 = tk.Button(button_frame, text="Clear",font=bold_font, command=clear_input, bg="#fe7575", fg="#000000", width=10)
    btn2.pack(side=tk.LEFT, padx=5, pady=5)

# - - Main Program - - 

def start_program():
    global root, status_label, top_frame, text_font, menu_bar, bold_font, note_area, tab_control, context_menu
    root = tk.Tk()
    root.title("Case Note Builder - Tool by Sam Collett")
    root.geometry("800x600")
    root.update_idletasks()
    root.configure(bg="#1e1e2f")
    bold_font = font.Font(family="Verdana", weight="bold", size=10)
    text_font = font.Font(family="Verdana", size=initial_font_size)
    # Create the top menu bar
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)
    # Frame for the status and timer
    top_frame = tk.Frame(root, bg="#333333")
    top_frame.pack(fill=tk.X)
    # Status label (Will stretch across available space)
    status_label = tk.Label(top_frame, text="Welcome!", font=("Helvetica", 10, "bold"), bg="#333333", fg="#ffffff", anchor="w")
    status_label.pack(side=tk.LEFT, fill=tk.X, padx=22, pady=2)  # Fill horizontally, with padding

    load_paned_windows()
    # Editable text area
    note_area = tk.Text(note_frame, wrap=tk.WORD,undo=True, width=60, height=30, bg="#2d2d44", fg="#ffffff", insertbackground="#ffffff", font=(text_font))
    note_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Right-side input panel with tabs
    tab_control = ttk.Notebook(root)
    tab_control.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=5, pady=5)

    # Add the note_area and tab_control to the PanedWindow
    paned_window.add(note_frame)
    paned_window.add(tab_control)

    # Right click menu
    context_menu = tk.Menu(root, tearoff=0)
    # Create the right-click menu
    context_menu = tk.Menu(root, tearoff=0)
    context_menu.add_command(label="Cut", command=cut_text)
    context_menu.add_command(label="Copy", command=copy_text)
    context_menu.add_command(label="Copy All", command=copy_to_clipboard)
    context_menu.add_command(label="Paste", command=paste_text)
    context_menu.add_separator()
    context_menu.add_command(label="Undo", command=paste_text)
    context_menu.add_command(label="Redo", command=paste_text)
    context_menu.add_separator()
    context_menu.add_command(label="Clear All", command=clear_input)
    context_menu.add_separator()
    submenu = tk.Menu(context_menu, tearoff=0)
    #submenu.add_command(label="Option 1", command=testerFunc)
    #submenu.add_command(label="Option 2", command=lambda: print("Option 2 selected"))
    #context_menu.add_cascade(label="More Options", menu=submenu)
    note_area.bind("<Button-3>", show_context_menu)
    root.bind("<Control-z>", undo_text)

    # Start periodic spell checking
    root.after(3000, check_spelling)
    # Load page elements
    load_case_input()
    load_menubar(root)
    populate_cases_menu()
    load_timer()
    # Load Tabs
    load_general_tab()
    load_email_top_tab()
    load_search_tab()
    load_other_tab()
    # Set status message
    update_status_message("Welcome - All modules loaded!","info ")

filename = 'data.csv'
csv_file = 'config.csv'
settings = read_settings(csv_file)

user_placeholder = "Enter user"
role_placeholder = "Enter role"
email_placeholder = "Enter email"
initial_font_size = int(settings.get("font_size"))
time_in_mins    = 40
time_left       = time_in_mins * 60  
flash_timer     = False


if __name__ == "__main__":
    start_program()
    root.mainloop()
