from        settings.debug import write_debug as log_debug_action
import      requests
import      csv
import      customtkinter as ctk
from        tkinter         import      messagebox, ttk, font, filedialog, Menu
import      webbrowser
from        settings.debug import read_settings_debug as read_settings


# Version Control
# Get the latest version from github
def get_version_from_github():
    log_debug_action(f"Get Version from Github function called")
    github_url = "https://raw.githubusercontent.com/CollettoS/Case-Builder/main/config.csv"
    try:
        response = requests.get(github_url)
        response.raise_for_status()  # Will raise an error for bad responses (e.g., 404)
        
        # Parse the CSV from the raw GitHub content
        reader = csv.DictReader(response.text.splitlines())
        for row in reader:
            if row.get("setting_name") == "version":
                log_debug_action(f"Current Github version found")
                return row.get("setting_value")
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Failed to fetch version from GitHub: {e}")
        log_debug_action(f"Could not find current version on github")
        return None
# Compare version from github to the local version.
def compare_versions(proc=1):
    settings = read_settings()

    log_debug_action(f"Compare versions process started...")
    global up_to_date, local_version, github_version
    local_version = settings.get("version")
    github_version = get_version_from_github()
    if proc == 1:
        log_debug_action(f"Compare Versions Process 1")
        if local_version is None or github_version is None:
            log_debug_action(f"Compare Versions: FAILED no versions avaiable")
            return  # If either version is not available, exit early
        
        if local_version == github_version:
            log_debug_action(f"Version is up to date! {local_version}")
            up_to_date = True
        else:
            log_debug_action(f"Tool is out of date.")
            show_version_update_message(local_version, github_version)
    if proc == 2:
        log_debug_action(f"Compare Version Process 2")
        if local_version is None or github_version is None:
            msg = f"V{local_version}"
            return msg
        
        if local_version == github_version:
            msg = f"V{local_version}"
            return msg
        else:
            msg = f"V{local_version} - New update Available: V{github_version}"
            return msg
# Update Available window
def show_version_update_message(local_version, github_version):
    # Create a new top-level window
    log_debug_action(f"Show verion message displayed")
    window = ctk.CTkToplevel()
    window.title("Version Update Available")
    window.geometry("400x300")
    window.resizable(False, False)
    window.attributes("-topmost", True)

    # Create a bold font for the title
    title_font = ctk.CTkFont(family="Helvetica", size=22, weight="bold")
    text_font = ctk.CTkFont(family="Helvetica", size=14)

    # Add a title label
    title_label = ctk.CTkLabel(window, text="A New Update is Available!", font=title_font, text_color="#FF5733")
    title_label.pack(pady=(20, 10))

    # Message details
    message = (
        f"Current version:  V{local_version}\n"
        f"Latest version:   V{github_version}\n\n"
        "Please update your tool by visiting the link below:\n"
        "Replace your current files with the updated ones."
    )

    # Add a message label
    message_label = ctk.CTkLabel(window, text=message, font=text_font, justify="left", wraplength=360)
    message_label.pack(padx=20, pady=10)

    # GitHub link
    github_link = "https://github.com/CollettoS/Case-Builder"
    link_label = ctk.CTkLabel(
        window, text=github_link, text_color="#007BFF", cursor="hand2", font=text_font
    )
    link_label.pack(pady=(5, 15))

    # Open GitHub link when clicked
    def open_github_link(event):
        webbrowser.open(github_link)

    link_label.bind("<Button-1>", open_github_link)

    # Add a close button
    close_button = ctk.CTkButton(
        window,
        text="Close",
        command=window.destroy,
        fg_color="#4C9CD7",
        hover_color="#368BB7",
        font=("Verdana", 12, "bold"),
    )
    close_button.pack(pady=10)

    # Center the window on the screen