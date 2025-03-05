# flask based host to use for url observance 
from flask import Flask, render_template, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logs')
def logs():
    return jsonify({"status": "No threats detected"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
