from flask import Flask, request, jsonify, render_template_string
import random

app = Flask(__name__)

random_message = [
  "Make it a magnificent day!",
  "Today's trouble? Tackle it with a smile!",
  "Winning day! Go get 'em!",
  "Thoughtful day! Take a moment to appreciate something small.",
  "Fantastic day! It's time to unwind and recharge.",
  "Sensational day! Make it a day of adventure.",
  "Sunny day! Relax, reflect, and refuel.",
  "Every day is a chance to learn and grow. Seize it!",
  "Believe in yourself and your dreams. They can come true!",
  "Challenges are opportunities in disguise. Embrace them!"
]


@app.route('/api')
def api():
    if request.headers.get("Host") != "127.0.0.1":
        return "You are not allowed to access this API"
        
    return random.choice(random_message)

@app.route('/admin')
def admin():
    if request.headers.get("Host") != "127.0.0.1":
        return "You are not allowed to access this page"

    return render_template_string(open('flag.txt').read())

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5001)