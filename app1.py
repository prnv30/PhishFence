# importing required libraries
from xgboost import XGBClassifier
from feature1 import featureExtraction
import numpy as np
import pandas as pd
from sklearn import metrics
import pickle

file = open("model1.pkl", "rb")
gbc = pickle.load(file)
file.close()
url = "http://www.eki-net.con-aescceeeeaas.hyhowu.top/jp.php"
obj = featureExtraction(url)
x = np.array(obj.getFeaturesList()).reshape(1, 15)
print(x)
y_pred = gbc.predict(x)[0]
print(y_pred)