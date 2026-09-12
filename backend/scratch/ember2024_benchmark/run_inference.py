import time
import os
import psutil
import lightgbm as lgb
from thrember.model import predict_sample
from thrember.features import PEFeatureExtractor
import numpy as np

model_path = r"C:\Users\Anup Kumar\Desktop\projects\CiphR\backend\scratch\ember2024_benchmark\EMBER2024_APK.model"
apk_path = r"C:\Users\Anup Kumar\Desktop\projects\CiphR\backend\tests\fixtures\ApiDemos-debug.apk"

def get_ram():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024

print("--- EMBER2024 APK Benchmark ---")
print(f"Base RAM: {get_ram():.2f} MB")

t0 = time.time()
print(f"Loading model: {model_path}")
booster = lgb.Booster(model_file=model_path)
t1 = time.time()
print(f"Model loaded in {t1 - t0:.4f} seconds")
print(f"RAM after model load: {get_ram():.2f} MB")

print(f"\nReading APK: {apk_path}")
with open(apk_path, "rb") as f:
    bytez = f.read()

t2 = time.time()
extractor = PEFeatureExtractor()
features = extractor.feature_vector(bytez)
t3 = time.time()
print(f"\nFeature extraction completed in {t3 - t2:.4f} seconds")
print(f"Feature vector shape: {features.shape}")

t4 = time.time()
print("\nRunning inference...")
try:
    score = booster.predict([features])[0]
    t5 = time.time()
    print(f"Inference completed in {t5 - t4:.4f} seconds")
    print(f"Model Score: {score}")
    print(f"RAM after inference: {get_ram():.2f} MB")
except Exception as e:
    import traceback
    traceback.print_exc()

