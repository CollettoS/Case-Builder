import customtkinter as ctk
import csv
import os

# Function to add data to CSV
def add_to_csv():
    entity = entity_entry.get().strip()
    note = note_entry.get().strip()

    if not entity:  # Ensure entity is not empty
        status_label.configure(text="Entity cannot be empty!", text_color="red")
        return

    file_path = "settings/entity_notes.csv"
    file_exists = os.path.isfile(file_path)

    # Write data to CSV
    with open(file_path, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Entity", "Note"])  # Write header if new file
        writer.writerow([entity, note])

    # Confirmation message
    status_label.configure(text="Entry added successfully!", text_color="green")

    # Clear fields after adding
    entity_entry.delete(0, "end")
    note_entry.delete(0, "end")

def entitity_manager_window():
    global entity_entry, note_entry, status_label
    # Initialize window
    ctk.set_appearance_mode("dark")  # Options: "dark", "light", "system"
    ctk.set_default_color_theme("blue")  # Theme color

    add_entity_window = ctk.CTk()  # Renamed from 'root'
    add_entity_window.title("Entity Note Manager")
    add_entity_window.geometry("600x180")

    # Grid Layout
    add_entity_window.grid_columnconfigure(0, weight=1)
    add_entity_window.grid_columnconfigure(1, weight=1)

    # Labels
    entity_label = ctk.CTkLabel(add_entity_window, text="Entity", font=("Arial", 14, "bold"))
    entity_label.grid(row=1, column=0, padx=10, pady=(10, 5), sticky="w")

    note_label = ctk.CTkLabel(add_entity_window, text="Note", font=("Arial", 14, "bold"))
    note_label.grid(row=1, column=1, padx=10, pady=(10, 5), sticky="w")

    # Entry Fields
    entity_entry = ctk.CTkEntry(add_entity_window, width=150)
    entity_entry.grid(row=2, column=0, padx=5, pady=5)

    note_entry = ctk.CTkEntry(add_entity_window, width=400)
    note_entry.grid(row=2, column=1, padx=5, pady=5)

    # Add Button
    add_button = ctk.CTkButton(add_entity_window, text="Add", command=add_to_csv)
    add_button.grid(row=3, column=0, columnspan=2, pady=10)

    # Status Label
    status_label = ctk.CTkLabel(add_entity_window, text="", font=("Arial", 12))
    status_label.grid(row=0, column=0, columnspan=2, pady=5)

    # Run the application
    add_entity_window.mainloop()
