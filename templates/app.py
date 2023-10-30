
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
    return render_template("home.html")

@app.route("/predict", methods = ["GET", "POST"])
@cross_origin()
def predict():
    if request.method == "POST":
    
        url = request.form["url_get"] 
        
        # feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
        #               'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
        #               'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards']

        # x=getFeaturs(url_get)
        # exrcat features
        
        #data_frame = pd.DataFrame(data=[x],columns=feature_names) 
                    
    
        
        
        obj = featureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 15)
        print(x)
        y_pred = model.predict(x)[0]
        print(y_pred)
        output="Phishy";
        if(y_pred==0):
            output="Safe"
        
        
        return render_template('home.html', prediction_text="The website {} is {}.".format(url,output))

    return render_template("home.html")

                
                
        
            
if __name__ == "__main__":
    app.run(debug=True)