## 🧩 How to Add the Chrome Extension

Follow the steps below to load the **Phishing Website Detection** extension into Google Chrome.

---

### 1. Open the Chrome Extensions Page

- Open **Google Chrome**
- In the address bar, navigate to:

```text
chrome://extensions/
```

- Press **Enter**

---

### 2. Enable Developer Mode

- In the **top-right corner**, toggle **Developer mode** **ON**
- Additional options like **Load unpacked** will appear

---

### 3. Load the Extension

- Click **Load unpacked**
- Select the folder containing the extension files:
  - `manifest.json`
  - `background.js`
  - `icons/` (if applicable)

- Click **Select Folder**

✅ The extension is now installed locally.

---

### 4. Verify Installation

- The extension will appear in the extensions list
- (Optional) Click the **pin icon** to show it in the Chrome toolbar
- Open the **Developer Console** (`Ctrl + Shift + I`) to view logs if required

---

### 5. Start Using the Extension

- Ensure the FastAPI backend is running:

```bash
uvicorn app:app --reload
```

- Open any website (e.g., `https://example.com`)
- The extension will automatically analyze the website and:
  - Show a **⚠️ alert** if the site is phishing
  - Display a **green badge** for legitimate websites

---

### ⚠️ Notes

- This extension is loaded in **Developer Mode** (local testing)
- The backend API must be available at:

```text
http://127.0.0.1:8000/predict
```

- To publish the extension publicly, it must be uploaded to the **Chrome Web Store**

---

### 🛠️ Troubleshooting

- Make sure **Developer mode** is enabled
- Verify the backend server is running
- Check extension permissions in `manifest.json`

---

If you want, I can also add:

- a **screenshots section**
- **permissions explanation**
- **Chrome Web Store deployment steps**
