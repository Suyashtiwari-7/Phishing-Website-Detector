# 🛡️ Phishing Website Detector (Security + ML)

An interactive AI-powered web application to detect phishing websites based on URL features. Built with **Flask**, **Scikit-learn**, and **Plotly** for real-time prediction and visualization.

---

## 📌 Features

- ✅ Classifies URLs as **Phishing** or **Legitimate**
- ✅ Extracts and visualizes key URL features
- ✅ Trained with a Random Forest classifier
- ✅ Responsive web interface using Flask + HTML
- ✅ Visual output with Plotly bar chart

---

## 🧠 Technologies Used

| Category         | Tools/Libraries                        |
|------------------|----------------------------------------|
| Language         | Python                                 |
| ML/AI            | Scikit-learn, Pandas, Joblib           |
| Web Framework    | Flask                                  |
| Visualization    | Plotly                                 |
| Feature Handling | Custom Python Logic (features.py)      |
| UI               | HTML (Jinja2 templating)               |

---

## 📂 Project Structure

PhishingWebDetector/
├── app.py                 # Flask web app
├── features.py            # URL feature extraction logic
├── train_model.py         # Model training script
├── malicious_phish.csv    # Dataset (Kaggle)
├── model/
│   └── phishing_model.pkl # Saved ML model
├── templates/
│   └── index.html         # Frontend template
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation



---

## 🚀 How to Run

### 1. Clone or Download

```bash
git clone https://github.com/Suyashtiwari-7/PhishingWebDetector.git
cd PhishingWebDetector
```

### 📦 Step 2: Install Dependencies

If you already have requirements.txt:
```bash
pip install -r requirements.txt
```
Or manually install them:
```bash
pip install flask pandas scikit-learn plotly joblib
```

### 🤖 Step 3: Train the ML Model

```bash
python train_model.py
```
Output:
✅ Model trained and saved to model/phishing_model.pkl


### 🌐 Step 4: Start the Flask Web App

```bash
python app.py
```
Then open this URL in your browser:
```bash
http://127.0.0.1:5000
```
# 📊 Sample Output

🔒 Legitimate Site        ← Safe website input


<img width="1890" height="967" alt="image" src="https://github.com/user-attachments/assets/aab5d645-33e1-44a0-bff3-1cc7e66e1915" />


⚠️ Phishing Site          ← Dangerous or fake link


<img width="1900" height="971" alt="image" src="https://github.com/user-attachments/assets/7b45403a-f587-422f-8f0a-296b972720c3" />


📈 Feature Visualization  ← Shown as an interactive Plotly bar chart

# 📁 Dataset Source
Kaggle – Malicious and Phishing URL Dataset:
```bash
https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
```
# ✨ Future Improvements

- Add WHOIS & domain age analysis
- Deploy app to Render or Railway
- Create a Chrome browser extension

# 🤝 Author

Suyash Tiwari  
Final Year B.Tech CSE Student  
AI & Security Enthusiast
