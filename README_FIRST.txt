DATAFIX - AUTONOMOUS DATA QUALITY AND REPAIR ENGINE
===================================================

OPEN IN VS CODE
1. Extract the complete ZIP folder.
2. In VS Code choose File > Open Folder and select DataFix_VSCode_Project.
3. Make sure Python 3.10 or newer is installed.
4. Double-click RUN_DATAFIX.bat, OR open the VS Code terminal in this folder and run:

   py -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   python app.py

5. Open http://127.0.0.1:5000 in your browser.
6. Keep the terminal open while using the website. Press Ctrl+C to stop it.

FEATURES
- Local email/password registration, login and logout.
- CSV, XLSX, XLS and selectable-text/table PDF upload (25 MB maximum).
- Checks for missing cells, duplicate rows, invalid emails, invalid phone lengths,
  unparseable dates, extra spaces, mixed capitalization in likely category fields,
  invalid numeric values in likely numeric fields, negative domain values and
  potential IQR numeric outliers.
- Quality score (heuristic indicator, not a certified standard).
- Selectable repair actions: remove duplicates, fill missing numeric values with
  medians, fill missing text with the most frequent value, trim spaces, normalize
  email addresses and standardize parseable dates.
- Clean CSV and Excel downloads, issue CSV and detailed PDF report.

IMPORTANT LIMITATIONS
- Scanned/image-only PDFs need OCR; only selectable text/table PDFs are supported.
- Outliers are suggestions for review, not necessarily errors.
- Automated repairs can change data. Review the cleaned dataset before using it.
- Uploaded dataset content is held in server memory and is cleared when the server
  stops or restarts. Download your cleaned data and reports before stopping.
- This is a local development application, not a production internet deployment.
- The supplied datafix_users.db is preserved. If it contains your existing account,
  use the same email and password. If no account exists, register on the login page.
- .datafix_secret is created automatically on first run. Keep it in this folder
  between runs so browser sessions remain valid.

FILES
app.py                         Main Flask app (backend + embedded web pages)
requirements.txt               Python dependencies
RUN_DATAFIX.bat                Windows setup and startup helper
datafix_users.db               Existing local user database
DataFix_Error_Test_Dataset.csv Sample dataset with deliberate errors
DataFix_Error_Test_Dataset.pdf Selectable-table PDF test file

For a fresh install, the first startup requires an internet connection to install
Python packages. Do not delete datafix_users.db or .datafix_secret.
