from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_socketio import SocketIO
import time
import datetime
import logging

app = Flask(__name__)

socketio = SocketIO(app)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Simulate network delay
    time.sleep(0.5)
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n[{timestamp}] ALARM: Incoming POST /login", flush=True)
    print(f"  --> Incoming payload trying Username: '{username}' | Password: '{password}'", flush=True)
    
    if username == "patient001" and password == "hospital@123":
        print(f"  [+] RESULT: MATCH FOUND! Access granted to portal.", flush=True)
        return jsonify({"status": "success"})
    else:
        print(f"  [-] RESULT: ACCESS DENIED. Invalid credentials.", flush=True)
        return jsonify({"status": "failed"})

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/visualise')
def visualise():
    return render_template('visualiser.html')

@app.route('/trigger_attack', methods=['POST'])
def trigger_attack():
    payload = request.get_json()
    print("\n[!] Received external command to trigger visual attack on browsers!", flush=True)
    # Broadcast to all connected clients on the index page
    socketio.emit('start_attack', payload)
    return jsonify({"status": "triggered"})

if __name__ == '__main__':
    print("Starting MediCare General Hospital Server (with WebSockets) on port 8080...")
    socketio.run(app, host='0.0.0.0',port=8080, debug=False)






