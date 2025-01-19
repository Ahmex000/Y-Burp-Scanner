### Ahmex000-Burp-Scanner

This Burp Suite extension is designed to automatically detect sensitive keywords in HTTP responses during penetration testing. By identifying potential sensitive data leaks, it assists penetration testers in quickly uncovering vulnerabilities.

---

### Features
- Scans HTTP responses for predefined sensitive keywords.
- Highlights the location of the detected keywords in the response body.
- Categorizes issues based on severity (e.g., High, Medium).
- Provides an easy-to-use framework for adding custom keywords.

---

### How It Works
1. The extension listens to all HTTP responses intercepted or sent by Burp Suite.
2. It parses the response body and searches for sensitive keywords defined in the `KEYWORDS` dictionary.
3. If a match is found:
   - The keyword is highlighted in the response body.
   - A new issue is added to the Burp Suite's issue list with detailed information.
4. Severity levels are determined based on the sensitivity of the detected keyword.

---

### Installation
1. Clone or download the extension files.
2. Open Burp Suite and navigate to the **Extender** tab.
3. Click on **Add**, then select the downloaded Python file.
4. Ensure Jython is configured in Burp Suite for the extension to run.

---

### Configuration
You can customize the `KEYWORDS` dictionary in the code to add or modify the keywords and their respective severity levels.

Example:
```python
KEYWORDS = {
    "password": "High",
    "api_key": "High",
    "private_key": "Critical",
}
```

---

### Usage
1. Load the extension into Burp Suite.
2. Intercept or send HTTP requests as usual.
3. Check the **Issues** tab for any flagged responses containing sensitive keywords.

---

### Contribution
Feel free to submit pull requests to enhance the functionality, add new features, or improve keyword detection.

---

### Disclaimer
This extension is a tool to assist penetration testers in identifying potential data leaks. It is the responsibility of the tester to ensure compliance with legal and ethical standards during its use.

----


### Last Update January 19, 2025, at 3:33 AM
I recently developed a Burp Suite extension designed to detect leaked data in JavaScript files. The extension focuses on identifying exposed information such as API keys, usage keys, and other sensitive data. In my latest update, made on January 19, 2025, at 3:33 PM, I expanded the keyword list to cover terms from various fields, including secrets and potential leakage indicators, for more accurate and comprehensive detection.


