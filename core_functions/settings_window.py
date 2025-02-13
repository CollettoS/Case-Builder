import customtkinter as ctk
import tkinter as tk
from settings.debug import read_settings_debug as read_settings
from core_functions.version_control import compare_versions
import csv
from tkinter import messagebox

def open_settings_menu(root, proc=0):
    global settings_window
    if proc == 1:
        return
    if root is None or not isinstance(root, ctk.CTk):
        print("Error: root is not a valid CTk instance!")
        return
    csv_file = 'config.csv'
    settings = read_settings(csv_file)
    
    settings_window = ctk.CTkToplevel(root)
    settings_window.title("Settings")
    settings_window.geometry("400x500")
    settings_window.configure(bg="#1e1e2f")
    settings_window.attributes("-topmost", True)

    notebook = ctk.CTkTabview(settings_window)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)
    
    general_tab = notebook.add("General")
    appearance_tab = notebook.add("Appearance")
    advanced_tab = notebook.add("Advanced")
    
    # General Tab
    version = compare_versions(2)
    ctk.CTkLabel(general_tab, text=f"Case Builder: {version}", font=("Arial", 14)).pack(anchor="w", pady=5)
    
    spell_check_value = ctk.BooleanVar(value=settings.get("spell_check") == "True")
    timer_value = ctk.BooleanVar(value=settings.get("enable_timer") == "True")
    email_tab_value = ctk.BooleanVar(value=settings.get("enable_email_tab") == "True")
    
    ctk.CTkCheckBox(general_tab, text="Spell Checker", variable=spell_check_value).pack(anchor="w")

    # Appearance Tab
    ctk.CTkLabel(appearance_tab, text="Theme:").pack(anchor="w")
    theme_var = ctk.StringVar(value="Dark")
    theme_dropdown = ctk.CTkComboBox(appearance_tab, variable=theme_var, values=["Dark", "Light", "System Default"])
    theme_dropdown.pack(anchor="w", pady=5)
    
    font_size_var = ctk.StringVar(value=str(settings.get("font_size")))
    ctk.CTkLabel(appearance_tab, text="Font Size:").pack(anchor="w")
    font_size_spinbox = ctk.CTkEntry(appearance_tab, textvariable=font_size_var, width=50)
    font_size_spinbox.pack(anchor="w", pady=5)
    
    # Advanced Tab
    api1_var = ctk.StringVar(value=str(settings.get("abuseipdb_api")))
    api2_var = ctk.StringVar(value=str(settings.get("vt_api")))
    debug_var = ctk.BooleanVar()
    
    ctk.CTkLabel(advanced_tab, text="AbuseIPDB API Key:").pack(anchor="w")
    ctk.CTkEntry(advanced_tab, textvariable=api1_var, width=300).pack(anchor="w", pady=5)
    ctk.CTkLabel(advanced_tab, text="VirusTotal API Key:").pack(anchor="w")
    ctk.CTkEntry(advanced_tab, textvariable=api2_var, width=300).pack(anchor="w", pady=5)
    
    debug_var = ctk.BooleanVar(value=settings.get("debug_mode") == "True")

    ctk.CTkCheckBox(advanced_tab, text="Enable Debugging", variable=debug_var).pack(anchor="w", pady=5)
    
    # Save & Close Buttons
    button_frame = ctk.CTkFrame(settings_window)
    button_frame.pack(side="bottom", fill="x", pady=10)
    
    ctk.CTkButton(button_frame, text="Save", command=lambda: save_settings(spell_check_value, debug_var, font_size_var, api1_var, api2_var)).pack(side="right", padx=5)
    ctk.CTkButton(button_frame, text="Close", command=settings_window.destroy).pack(side="right", padx=5)
    
    settings_window.mainloop()


def save_settings(spell_check_var, debug_var, font_size_var, api1, api2):

    csv_file = 'config.csv'
    settings = read_settings(csv_file)
    previous_font_size = settings.get("font_size")

    # Retrieve the settings from input fields and variables
    sc_enabled = spell_check_var.get()    
    debug_enabled = debug_var.get()
    font_size = font_size_var.get()
    api1 = api1.get()
    api2 = api2.get()
    # Print the settings to verify 

    # Update the settings dictionary and write to CSV
    settings["spell_check"] = str(sc_enabled)  # Convert boolean to string for CSV
    settings["debug_mode"] = str(debug_enabled)
    settings["font_size"] = str(font_size)
    settings["abuseipdb_api"] = str(api1)
    settings["vt_api"] = str(api2)

    # Save updated settings to the CSV
    new_font = int(font_size)
    done = write_settings(csv_file, settings)
    if done:
        check_font_size_and_notify(previous_font_size, font_size)

def write_settings(csv_file, settings):
    # print("----")
    # print(settings)
    try:
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["setting_name", "setting_value"])  # Write header
            for setting_name, setting_value in settings.items():
                # print(f"{setting_name} - {setting_value}")
                writer.writerow([setting_name, setting_value])  # Write key-value pairs
        
        read_settings(csv_file)  # Reload settings
        return True
    except:
        return False


def check_font_size_and_notify(previous_font_size, new_font_size):

    if new_font_size != previous_font_size:
        messagebox.showinfo("Appearance Updated", "Font size changed. Restart the program to apply changes.")
        previous_font_size = new_font_size  # Update the stored font size
    else:
        messagebox.showinfo("Settings Saved", "Settings saved successfully.")
    settings_window.destroy()
