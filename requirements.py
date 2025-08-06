import os
import subprocess

requirements = ["colorama", "rich"]

print("🔧 Installing requirements...")
for pkg in requirements:
    subprocess.call([sys.executable, "-m", "pip", "install", pkg])
print("✅ Done.")
