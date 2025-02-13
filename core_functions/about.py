import customtkinter as ctk
import webbrowser
from PIL import Image

# Sample Team Members
team_members = [
    ("Sam Collett", "Tool Developer"),
    ("Alex Jenkins", "Plugin Developer"),
    ("Ryan Ferns", "Contributor and Tester"),
]

def open_github():
    webbrowser.open("https://github.com/CollettoS/Case-Builder")  

def open_about_window():
    about = ctk.CTkToplevel()
    about.title("About")
    about.geometry("500x450")
    about.resizable(False, False)

    # === Top Section ===
    top_frame = ctk.CTkFrame(about)
    top_frame.pack(fill='x', pady=10, padx=10)

    # Load image using PIL and convert to CTkImage
    pil_image = Image.open("core_functions/logo.png")
    logo = ctk.CTkImage(light_image=pil_image, dark_image=pil_image, size=(200, 200))
    
    # Logo (Left)
    logo_label = ctk.CTkLabel(top_frame, image=logo, text="")
    logo_label.grid(row=0, column=0, padx=10, pady=10)

    # Title & About Text (Right)
    text_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
    text_frame.grid(row=0, column=1, sticky="w", padx=10)
    
    title_label = ctk.CTkLabel(text_frame, text="Case Note Builder", font=("Arial", 18, "bold"))
    title_label.pack(anchor="w")
    
    about_text = "A powerful tool designed to streamline SOC case documentation."
    desc_label = ctk.CTkLabel(text_frame, text=about_text, font=("Arial", 12), wraplength=250, justify="left")
    desc_label.pack(anchor="w")

    # === Team Section ===
    team_frame = ctk.CTkFrame(about)
    team_frame.pack(fill='x', padx=10, pady=10)
    
    team_label = ctk.CTkLabel(team_frame, text="Project Team", font=("Arial", 14, "bold"))
    team_label.pack(anchor="w")
    
    for name, role in team_members:
        member_label = ctk.CTkLabel(team_frame, text=f"{name} \t-\t {role}", font=("Arial", 12))
        member_label.pack(anchor="w", padx=10)


    button_frame = ctk.CTkFrame(about)
    button_frame.pack(fill='x', padx=10, pady=10)
    # === GitHub Link ===
    github_button = ctk.CTkButton(button_frame, text="View on GitHub", command=open_github)
    github_button.grid(row=0, column=0, padx=10, pady=10)

    close_button = ctk.CTkButton(button_frame, text="Close", fg_color="red", text_color="white", command=about.destroy)
    close_button.grid(row=0, column=1, padx=10, pady=10)

    about.mainloop()
