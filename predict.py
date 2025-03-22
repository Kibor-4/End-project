import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import mean_squared_error, r2_score
from sklearn.preprocessing import LabelEncoder
import joblib
import logging

logging.basicConfig(level=logging.INFO)

try:
    # 1. Load Data
    data = pd.read_excel("Combine.xlsx")  # Use relative path

    # 2. Data Preprocessing
    # a. Handle Missing Values
    for col in data.select_dtypes(include=['number']).columns:
        data[col] = data[col].fillna(data[col].mean())

    for col in data.select_dtypes(exclude=['number']).columns:
        data[col] = data[col].fillna(data[col].mode()[0])

    # b. Encode Categorical Features
    label_encoders = {}
    categorical_cols = ['PropertyTitle', 'Location']
    for col in categorical_cols:
        le = LabelEncoder()
        data[col] = le.fit_transform(data[col])
        label_encoders[col] = le

    # 3. Feature Selection and Target Variable
    features = ['PropertyTitle', 'Location', 'Bedroom', 'Bathroom']
    X = data[features]
    y = data['Price']

    # 4. Split Data into Training and Testing Sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 5. Decision Tree Regressor
    regressor = DecisionTreeRegressor(random_state=42)
    regressor.fit(X_train, y_train)

    # 6. Model Persistence
    joblib.dump(regressor, 'decision_tree_model.joblib')
    joblib.dump(label_encoders, 'label_encoders.joblib')

    # 7. Performance Evaluation
    y_pred = regressor.predict(X_test)
    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    logging.info(f"Decision Tree Mean Squared Error: {mse}")
    logging.info(f"Decision Tree R-squared: {r2}")

    # 8. Convert Model to ONNX (replace sklearn_porter)
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    input_type = [('input', FloatTensorType([None, 4]))]
    onnx_model = convert_sklearn(regressor, initial_types=input_type)
    with open("decision_tree_model.onnx", "wb") as f:
        f.write(onnx_model.SerializeToString())
    logging.info("Model converted to ONNX successfully.")
except FileNotFoundError:
    logging.error("File not found.")
except Exception as e:
    logging.error(f"An error occurred: {e}")