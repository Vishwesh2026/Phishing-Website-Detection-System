# Phishing Website Detection System

This project is a Phishing Website Detection System that uses machine learning to classify URLs as either legitimate or phishing.

## Dependencies

The following dependencies are required to run the project. You can install them using pip:

```bash
pip install fastapi uvicorn scikit-learn pandas numpy joblib
```

## Setup and Execution

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Vishwesh2026/Phishing-Website-Detection-System.git
    cd Phishing-Website-Detection-System
    ```

2.  **Install the dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application:**

    ```bash
    uvicorn app:app --reload
    ```

    The application will be running at `http://127.0.0.1:8000`.

## Testing

You can test the application with the following URLs:

**Legitimate URLs:**

- `https://www.google.com`
- `https://www.github.com`
- `https://www.youtube.com`

**Phishing URLs:**

- `http://www.update-browser.com/`
- `http://www.facebook-login-security-check.com/`
- `http://www.paypal-secure-login.com/`
 