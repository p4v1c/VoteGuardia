from flask import Flask,render_template 
  
app = Flask(__name__) 
  
@app.route("/vote") 
def vote(): 
    return render_template('vote.html')

@app.route("/register") 
def register(): 
    return render_template('register.html')

@app.route("/result") 
def admin(): 
    return render_template('result.html')

@app.route('/')
def home():
   return render_template('index.html')


if __name__ == "__main__": 
    app.run(debug=False) 

