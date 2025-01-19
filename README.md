# Case Builder
A simple tool for SOC Analysts 

The Case Builder Tool is a local Python-based utility designed to assist SOC analysts in documenting case notes and generating reports efficiently. It integrates with APIs such as AbuseIPDB and VirusTotal to enhance threat intelligence during investigations. The tool is feature-rich and highly customizable to suit the needs of SOC teams.

---
## Important!!!

**Please read this file in full before use**

## Features

- **Case Note Management**  
  Save and organise case notes into categorized folders:
  - `saved_notes`: Stores completed case notes.
  - `open_cases`: Temporarily stores notes for ongoing cases, which are moved to `saved_notes` upon closure.

- **API Integration**  
  Lookup IP addresses and URLs using AbuseIPDB and VirusTotal APIs for file hashes

- **Search Previous Cases**     
  If you have seen a peice of information before in a closed case, this program will tell you. 

- **Spell Checking**  
  Automatic spell checking for your notes with support for enabling/disabling in settings.

- **Case Title**    
  This can either be left blank or filled.
  - If case title is entered the file will be saved as:
    `[case name] - [Todays Date].txt` e.g. `phishing-case-01-01-25.txt`
  - If no case title is entered the file will be saved as:
    `[todays Date] - [Three Digit Random Number].txt` e.g. `01-01-25-256.txt`

- **Customisable Settings**  
  Enable or disable specific features and configure API keys via the settings menu.

- **Keyboard Shortcuts**  
  Includes useful shortcuts like undo (Ctrl+Z) and context-sensitive actions.

- **Text Formatting**  
  Highlight text and process it through various functions for advanced formatting or analysis.


---

## Setup

### 1. Install Python
Download and install the latest version of Python from the [Windows Store](https://apps.microsoft.com/detail/9ncvdn91xzqp).

### 2. Install Required Packages
Open the command prompt and run the following command to install the required Python packages:
```
pip install requests pyspellchecker pycountry
```

### 3. Get API Keys
- [Signup for AbuseIPDB](https://www.abuseipdb.com/register) and obtain an API key.
- [Signup for VirusTotal](https://www.virustotal.com/gui/join-us) and obtain an API key.

### 4. Start the Program
1. Navigate to the folder where `case_builder.py` is located.
2. Right-click and open the terminal in that folder.
3. Run the program by typing:
   ```
   python case_builder.py
   ```

### 5. Configure Settings
1. Once the tool is open, go to `Options -> Settings -> Advanced`.
2. Insert your API keys in the provided fields and click "Save."
3. Enable or disable specific features in the settings menu.

---

## Additional Information

- **Saved Notes**: All completed case notes are stored in the `saved_notes` folder.
- **Open Cases**: Cases you have not finished working on are temporarily saved in the `open_cases` folder. Once you close a case with the "Next Case" button, it will automatically be moved to `saved_notes`.
- **Case Names** Adding a title in the top input box will save the case as the case title and todays date, if no title is inputted the case will be saved as todays date plus three random digits. **Dont worry!** this data can still be searched by the program.

---

## Example Usage

### Moving on after your case has been closed
1. Press the next case button
2. The case will be saved in `saved_notes`.

### Open a second case
1. Press **My cases**
2. Press **Add new case**
3. All open cases will be displayed in the my cases section

### Performing an IP Lookup
1. Enter the IP address into the input field.
2. Click the "Scan IP" button to query AbuseIPDB.
3. Results, such as the IP's abuse confidence score and country information, will be inserted into your notes.

### Performing an Hash Lookup
1. Enter the file hash into the input field.
2. Click the "Scan IP" button to query VirusTotal.
3. Results, such as the Author, file name, type and more will be inserted into your notes. 

### Writing Case Notes
1. Use the text editor to write detailed case notes.
2. Use the formatting options on the right to insert data like the user, role, email etc.
2. Highlight text and use right-click options to process specific content.

### Searching your cases
1. Search previous cases you have closed in the search tab.
2. When inputted data it will be searched accross your closed cases.
3. A message will display if you have seen that data before.

---


## Common Issues

### Error Searching IP or Hash
- This may indicate that the API key is invalid.
- Check the **Settings** menu to ensure your API key is correct.
- Make sure there are no blank spaces before or after the API key.
- Open `config.csv` to double-check the saved API key.

### No Results for Hash
- If no results are returned for a hash, it may not exist in the VirusTotal database.
- This could mean the hash has not been scanned or reported yet.

---

### Need More Help?
- Verify your API keys and configurations.
- If the issue persists, message **Sam** for support.

---

## Contributions
Feel free to suggest features or report issues via GitHub.

---