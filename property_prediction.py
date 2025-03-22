import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.svm import SVR
from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor
from sklearn.metrics import mean_squared_error, r2_score
from sklearn.tree import DecisionTreeRegressor, plot_tree
import matplotlib.pyplot as plt
import seaborn as sns

# 1. Load Data
data = pd.read_excel(r"C:\Users\LENOVO\Downloads\Destro\Combine.xlsx")
print(data.head(5))

# 2. Data Preprocessing
# a. Handle Missing Values
for col in data.select_dtypes(include=['number']).columns:
    data[col] = data[col].fillna(data[col].mean())

for col in data.select_dtypes(exclude=['number']).columns:
    data[col] = data[col].fillna(data[col].mode()[0])

# b. Encode Categorical Features
label_encoder = LabelEncoder()
categorical_cols = ['PropertyTitle', 'Location']
for col in categorical_cols:
    data[col] = label_encoder.fit_transform(data[col])

# 3. Feature Selection and Target Variable
X = data.drop('Price', axis=1)
y = data['Price']

# 4. Split Data into Training and Testing Sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Decision Tree Regressor
regressor = DecisionTreeRegressor(random_state=42)
regressor.fit(X_train, y_train)
y_pred = regressor.predict(X_test)
mse = mean_squared_error(y_test, y_pred)
r2 = r2_score(y_test, y_pred)
print(f"Decision Tree Mean Squared Error: {mse}")
print(f"Decision Tree R-squared: {r2}")