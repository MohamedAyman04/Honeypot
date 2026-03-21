import joblib
import pandas as pd

model = joblib.load("/data/model.pkl")

def detect(packet_size, func_code, is_write):
    X = pd.DataFrame([[packet_size, func_code, is_write]], columns=["length", "func_code", "is_write"])
    prediction = model.predict(X)
    return prediction[0]

def detect_stealth_drift(features):
    window = 20
    rolling_mean = features['pressure'].rolling(window=window).mean()
    rolling_std = features['pressure'].rolling(window=window).std()
    z_score = (features['pressure'] - rolling_mean) / rolling_std

    # Check for consistent upward drift with no actuator change
    if (features['pressure_delta'].tail(10) > 0).all() and (features['is_write'].tail(10) == 0).all():
        return True, "STEALTH_DRIFT_DETECTED"
    
    return False, "NORMAL"