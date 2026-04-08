import sys
from app import KerasAutoEncoderFeatureExtractor

# Hack to map the class correctly for unpickling
sys.modules['__main__'].KerasAutoEncoderFeatureExtractor = KerasAutoEncoderFeatureExtractor

import joblib
model = joblib.load('model.joblib')
print("Model unpickled successfully!")
