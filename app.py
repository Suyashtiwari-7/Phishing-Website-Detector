import os
import joblib
from flask import Flask, request, render_template
import plotly.graph_objs as go
import plotly.io as pio
from features import extract_features

app = Flask(__name__)

# ✅ Absolute path to model
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, "model", "phishing_model.pkl")
model = joblib.load(model_path)

# ✅ Feature labels for the graph
labels = ['URL Length', '@ Symbol', 'Subdomains', 'HTTPS', 'Suspicious Word']

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    plot_div = None

    if request.method == "POST":
        url = request.form["url"]
        features = extract_features(url)
        prediction = model.predict([features])[0]

        result = "🔒 Legitimate Site" if prediction == 0 else "⚠️ Phishing Site"

        # ✅ Create a bar graph using Plotly
        fig = go.Figure([go.Bar(x=labels, y=features)])
        fig.update_layout(title="Extracted URL Features", plot_bgcolor="white")
        plot_div = pio.to_html(fig, full_html=False)

    return render_template("index.html", result=result, plot_div=plot_div)

if __name__ == "__main__":
    app.run(debug=True)
