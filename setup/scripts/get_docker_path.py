import os

path = os.path.join(os.path.dirname(__file__)[:os.path.dirname(__file__).index("setup")])
print(path)
