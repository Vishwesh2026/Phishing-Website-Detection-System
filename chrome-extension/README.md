# 🧩 SafeSurf Chrome Extension v3.1

The **SafeSurf Extension** acts as the frontend client for the Phishing Website Detection system. It actively analyzes the URLs of the tabs you visit in real-time.

---

## 🚀 Features
- **Real-time Domain & URL Analysis:** Consults the background XGBoost model when a new tab resolves.
- **DNS Guard Awareness:** Detects NXDOMAIN entries seamlessly. 
- **Graceful Notification:** Alerts immediately via Chrome notifications when a high-risk or medium-risk phishing site is detected. 
- **WHOIS Intelligence:** Displays domain registrar, age, and creation data directly from the extension popup.

---

## 🛠️ How to Install (Developer Mode)

### 1. Open the Chrome Extensions Page
- Open **Google Chrome**
- In the address bar, navigate to:
  ```text
  chrome://extensions/
  ```

### 2. Enable Developer Mode
- In the **top-right corner**, toggle **Developer mode** to ON.

### 3. Load the Extension
- Click the **Load unpacked** button.
- Select the `chrome-extension/` folder inside your project directory.
- The `SafeSurf Extension` will now appear in your extensions list. Pin the shield icon to your toolbar for easy access!

---

## 🔌 Running the Backend API

For the extension to function, the local API must be running. It communicates via HTTP POST requests to `http://127.0.0.1:8000/api/v1/analyze`.

Start the backend API using:
```bash
uvicorn app.main:app --reload
```

---

## 🔎 How It Works

1. **Background Service Worker (`background.js`)**
   - Listens to tab updates.
   - Posts the URL to the local FastAPI backend.
   - Saves the result locally and changes the dynamic badge icon.
2. **Popup UI (`popup.html` & `popup.js`)**
   - Retrieves the cached prediction.
   - Displays a dynamic UI based on risk mapping (Invalid domain, Safe, or Phishing High/Medium/Low).
   - Serves an interface presenting domain age, WHOIS intelligence, and a quick redirect key to the comprehensive Deep Analysis dashboard.
