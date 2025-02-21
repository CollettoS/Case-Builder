name = "Escalation Builder"
enabled = False # Set so cannot be accessible through the SOC tools menu, this is to avoid any issues
id = 102
author = "Sam Collett"
description = "Tool to help build escalations"

def run(ents=[], alert=""):
    global step
    import customtkinter as ctk
    import tkinter as tk
    from datetime import datetime
    import csv
    import os
    from settings.debug import read_settings_debug as read_settings
    import core_functions.miscFuncs as mF



    # settings.get("debug_mode")
    settings = read_settings()
    checkboxes = {}  # Dictionary to store the checkbox variables
    inv_opts = [
        {'name': 'Ask for Investigation and Confirmation', 'text': 'Please could you investigate and confirm if this activity is legitimate.'},
        {'name': 'Ask for Confirmation', 'text': 'Please could you confirm if this activity is legitimate.'},
        {'name': 'Verfiy if operation was unsuccessful ', 'text': 'Please could you verify if this operation was unsuccessful'}

    ]


   
    def create_teams_msg(): 
        # Get the current date
        current_date = datetime.now()
        ryan = settings.get("esc_sign_name")
        # Format the date as 'Date: DD/MM/YYYY'
        formatted_date = current_date.strftime("Date: %d/%m/%Y")
        teams_text_raw = (
            f"Analyst Assigned: {ryan}", # Ryan your a legend for fixing this <3 
            f"Reviewed By: ",
            f"Case Link: ",
            f"Date: {formatted_date}",
            f"Environment: {client_name}",
            f"Escalation Summary: {alert_name}",
        )
        teams_text = "\n".join(teams_text_raw)
        return teams_text

    def copy_to_clipboard(input):
        input_text = input.get("1.0", tk.END).strip()
        root.clipboard_clear()
        root.clipboard_append(input_text)

    def create_teams_dump_msg_window():
        # Initialize CustomTkinter
        text = create_teams_msg()
        ctk.set_appearance_mode("Dark")
        root = ctk.CTk()
        root.title("Teams Dump Message")
        root.geometry("300x150")

        # Create an input box
        Tinput_box = ctk.CTkTextbox(root, width=200, height=100, wrap="word")
        Tinput_box.pack(pady=5, padx=20)
        Tinput_box.insert("1.0", text)

        # Create a "Copy" button
        copy_button = ctk.CTkButton(root, text="Copy", command= lambda: copy_to_clipboard(Tinput_box))
        copy_button.pack(pady=5)

        root.mainloop()


    def create_checkboxes():
        global checkboxes
        checkboxes = {}  # Dictionary to store the checkbox variables

        for key in data:
            var = ctk.BooleanVar()  # Create a BooleanVar for each checkbox
            checkbox = ctk.CTkCheckBox(frame, text=key, variable=var)
            checkbox.pack(side="top", anchor="w",)
            checkboxes[key] = checkbox  # Store the checkbox widget (not the BooleanVar)
        return checkboxes

    def get_individual_selected_values():
        global checkboxes, var
        selected_values = []
        for key, var in checkboxes.items():
            if var.get():  # If the checkbox is checked
                selected_values.append(data[key])  # Add the second value to the list
        return selected_values

    def create_input_box():
        global input_box
        input_box = ctk.CTkEntry(left_pane, width=250)
        input_box.pack(pady=5)
        return input_box
    
    def create_input_box2():
        global input_box2
        input_box2 = ctk.CTkEntry(left_pane, width=250)
        input_box2.pack(pady=5)
        return input_box

    def delete_all_checkboxes():
        global checkboxes  # Use the global checkboxes variable

        for checkbox in checkboxes.values():
            checkbox.destroy()  # Destroy the checkbox widget

        checkboxes.clear()  # Clear the dictionary

    def delete_input_box(proc):
        if proc == 1:
            input_box.destroy()
        elif proc == 2:
            input_box2.destroy()
        elif proc == 3:
            input_box.destroy()
            input_box2.destroy()



    # Insert text into the note area
    def insert_text(text):
        note_box.insert(ctk.END, text + "\n")

    def format_remidiation_text(numb, remidiation):
                
        if numb == 1:
            text_to_insert = f"{remidiation[0]}."
        elif numb == 2:
            text_to_insert = f"{remidiation[0]} and {remidiation[1]}."
        elif numb > 2:
            text_to_insert = ", ".join(remidiation[:-1]) + " and " + remidiation[-1] + "."
        else:
            text_to_insert = None
        
        return text_to_insert

    def get_role_ent():
        # Loop through the list and check if 'type' is 'User'
        for entity in ents:
            if entity['type'] == 'Role':
                return entity['ent']
        return None  # Return None if no 'User' is found

    def get_user_ent():
        # Loop through the list and check if 'type' is 'User'
        for entity in ents:
            if entity['type'] == 'User':
                return entity['ent']
        return None  # Return None if no 'User' is found

    def display_entities():
        for widget in frame.winfo_children():  # Clear any previous widgets in the frame
            widget.destroy()
        found = 0
        row_index = 0  # Row counter for layout
        for entity in ents:
            entity_type = entity['type']
            entity_ent = entity['ent']
            label = ctk.CTkLabel(frame, text=f"{entity_type}: {entity_ent}")
            label.grid(row=row_index, column=0, padx=10, pady=5, sticky="w")

            # Insert button for each entity
            insert_button = ctk.CTkButton(frame, text="Insert", width=10, command=lambda e_type=entity_type, e_ent=entity_ent: insert_entity(e_type, e_ent))
            insert_button.grid(row=row_index, column=1, padx=10, pady=5)

            row_index += 1
            found += 1
        if not found:
            label = ctk.CTkLabel(frame, text="No case entitles found")
            label.grid(row=row_index, column=0, padx=10, pady=5)



    
    def display_inv_options():
            for widget in frame.winfo_children():  # Clear any previous widgets in the frame
                widget.destroy()
            found = 0
            row_index = 0  # Row counter for layout
            for opts in inv_opts:
                name = opts['name']
                text = opts['text']
                label = ctk.CTkLabel(frame, text=f"{name}")
                label.grid(row=row_index, column=0, padx=5, pady=5, sticky="w")

                # Insert button for each entity
                insert_button = ctk.CTkButton(frame, text="Insert", width=10, command=lambda e_ent=text: insert_text(e_ent))
                insert_button.grid(row=row_index, column=1, padx=5, pady=5)

                row_index += 1
                found += 1
            if not found:
                label = ctk.CTkLabel(frame, text="No options found")
                label.grid(row=row_index, column=0, padx=10, pady=5)

    def clear_entities_list():
        for widget in frame.winfo_children():  # Destroy all widgets in the frame
            widget.destroy()

    def create_final_touches_buttons():
        
        button1 = ctk.CTkButton(frame, text="Sanitize URLs", width=20, command=lambda: mF.sanitize_urls(note_box))
        button1.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        button2 = ctk.CTkButton(frame, text="Add additional info", width=20, command=lambda: insert_text("\nAdditional Information:"))
        button2.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        button3 = ctk.CTkButton(frame, text="Generate teams dump message", width=20, command=create_teams_dump_msg_window)
        button3.grid(row=2, column=0, padx=10, pady=5, sticky="w")


    def insert_entity(type, entity):
        insert_text(f"{type}: {entity}")

    # Handle next step
    def next_step():
        global step, step_label, input_box, alert_name, client_name

        if  input_box and input_box.winfo_exists():
            input_value = input_box.get().strip()
            input_box.delete(0, ctk.END)  # Clear the input box if needed
        else:
            input_value = ""
        
        if  input_box2.winfo_exists():
            input_value2 = input_box2.get().strip()
            input_box2.delete(0, ctk.END)  # Clear the input box if needed
        else:
            input_value2 = ""

        if step == 0:
            client_name = input_value
            insert_text(f"Hello {input_value}")
            if alert:
                input_box.insert(0, alert)  # Insert the name if exists in the dictionary

        elif step == 1:
            alert_name = input_value
            insert_text(f"We are escalating this case to you as we have received an alert for {input_value}\n")
            
            user = get_user_ent()
            if user:  # Check if 'type' is 'user'
                input_box.insert(0, user)  # Insert the name if exists in the dictionary
            
        elif step == 2:
            details["User"] = input_value
            
            role = get_role_ent()

            if role:
                input_box.insert(0, role)  # Insert the role if exists in the dictionary
            if not details.get("User"):
                step = 4 # Skip to step 5
        elif step == 3:

            details["Role"] = input_value
        elif step == 4:
            details["Location"] = input_value
        elif step == 5: # Step 6
            details["Activity"] = input_value
            if not details.get("User") and not details.get("Role") and not details.get("Location"):
                insert_text(f"The following activity has been observed{details['Activity']}")
            elif not details.get("Role") and not details.get("Location"):
                insert_text(f"The user, {details['User']}, has been observed {details['Activity']}")
            elif not details.get("User"):
                insert_text(f"The following activity has been observed{details['Activity']}")
            elif not details.get("Location"):
                insert_text(f"The user, {details['User']}, who is a {details['Role']}, has been observed {details['Activity']}")
            else:
                insert_text(f"{details['User']}, who is a {details['Role']} normally located in {details['Location']}, has been observed {details['Activity']}")


            delete_input_box(1)
            display_entities()

        elif step == 6: #step 7 - enter evidence 
            clear_entities_list()
            display_inv_options()
        elif step == 7: # Remidiation
            clear_entities_list()
            create_checkboxes() # create the checkboxes for the next step 

        elif step == 8:
            remidiation = get_individual_selected_values()
            numb = int(len(remidiation))
            formatted_text = format_remidiation_text(numb, remidiation)
            if formatted_text:
                insert_text(f"If this activity is deemed malicious we reccomed {formatted_text}\n\n")
            
            delete_all_checkboxes()

            sign_text = settings.get("esc_sign")
            sign_name = settings.get("esc_sign_name")
            create_input_box()
            create_input_box2()
            input_box.insert(0, sign_text)
            input_box2.insert(0, sign_name)

        elif step == 9: # How to procede
            delete_input_box(3)
            insert_text(f"\n\n{input_value}\n{input_value2}")
            create_final_touches_buttons()

        elif step == 10:
            insert_text(f"Additional Information: {input_value}")

        step += 1
        if step < len(steps):
            step_label.configure(text=steps[step])
        else:
            step_label.configure(text="Escalation Note Completed")
            next_button.configure(state=ctk.DISABLED)

    # Initialize CustomTkinter
    ctk.set_appearance_mode("Dark")
    root = ctk.CTk()
    root.title("Escalation Builder - THIS IS STILL IN DEVELOPMENT!!!!!")
    root.geometry("700x500")

    # Load CSV data

    details = {"User": "", "Role": ("", "unknown"), "Location": ("", "unknown")}
    steps = [
        "Step 1: Enter Client Name", 
        "Step 2: Enter Alert", 
        "Step 3: Enter User Name", 
        "Step 4: Enter User Role", 
        "Step 5: Enter User Location", 
        "Step 6: Enter User Activity", 
        "Step 7: Enter Evidence",
        "Step 8: How to Proceed",     
        "Step 9: Remidiation",
        "Step: 10: Signature",

        "Step 11: Final Touches", 

    ]
    global data
    data = {
        "Reset Password": "resetting the users password",
        "Revoke current sessions": "revoking any current sessions",
        "Reset MFA": "reseting MFA",
        "Kill and quarantine": "killing and quarantining the file."

    }

    step = 0

    # Layout
    frame = ctk.CTkFrame(root)
    frame.pack(fill="both", expand=True, padx=10, pady=10)
    global left_pane
    left_pane = ctk.CTkFrame(frame)
    left_pane.pack(side="left", fill="both", expand=True, padx=5, pady=5)

    right_pane = ctk.CTkFrame(frame)
    right_pane.pack(side="right", fill="both", expand=True, padx=5, pady=5)

    # Left Panel - Input Box
    global step_label
    step_label = ctk.CTkLabel(left_pane, text=steps[step], font=("Arial", 14))
    step_label.pack(pady=5)
    txt_label = ctk.CTkLabel(left_pane, text="If this step does not apply, skip it.", font=("Arial", 10))
    txt_label.pack(pady=0)
    global input_box, input_box2
    create_input_box()
    create_input_box2()
    delete_input_box(2)

    next_button = ctk.CTkButton(left_pane, text="Next", command=next_step)
    next_button.pack(pady=5)

    frame = ctk.CTkFrame(left_pane)
    frame.pack(padx=20, pady=20)

    # Right Panel - Note Area
    note_box = ctk.CTkTextbox(right_pane, width=300, height=350, wrap="word")
    note_box.pack(pady=5, padx=5)


    root.mainloop()

