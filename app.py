
from flask import Flask, request, render_template
from flask_cors import cross_origin
import pickle
import pandas as pd
import numpy as np

from feature1 import featureExtraction

app = Flask(__name__)
model = pickle.load(open("model1.pkl", "rb"))

@app.route("/")
@cross_origin()
def home():
    return render_template("index.html")

@app.route("/predict", methods = ["GET", "POST"])
@cross_origin()
def predict():
    if request.method == "POST":
    
        url = request.form["url_get"] 
        obj = featureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 15)
        print(x)
        y_pred = model.predict(x)[0]
        print(y_pred)
        output="Phishy";
        if(y_pred==0):
            output="Safe"
        
        
        return render_template('index.html', prediction_text="The website looks {}.".format(output))

    return render_template("index.html")

       
if __name__ == "__main__":
    app.run(debug=True)