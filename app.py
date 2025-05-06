from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/dashboard', endpoint='dashboard')
def showDashboard():
    data = {
        "all_events": 42,  # To be replaced with real data
        "last_result": "Poor",
        "concerns": 3,
    }
    return render_template("dashboard.html", data=data)

@app.route('/reports', endpoint='reports')
def showReports():
    return render_template("reports.html")

@app.route('/alerts', endpoint='alerts')
def showAlerts():
    return render_template("alerts.html")

@app.route('/scans', endpoint='scans')
def showScans():
    return render_template("scans.html")

@app.route('/support', endpoint='support')
def showSupport():
    return render_template("support.html")

@app.route('/settings', endpoint='settings')
def showSettings():
    return render_template("settings.html")

# Run the server
if __name__ == "__main__":
    app.run(debug=True)