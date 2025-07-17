import os

# Ensure we're writing inside this script's folder
folder = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(folder, "requirements.txt")

packages = [
    "Flask",
    "pandas",
    "scikit-learn",
    "plotly",
    "tldextract",
    "joblib"
]

with open(file_path, "w") as f:
    f.write("\n".join(packages))

print("✅ requirements.txt created in:", file_path)

install_now = input("Install packages now? (y/n): ")
if install_now.lower() == "y":
    os.system(f"pip install -r {file_path}")
