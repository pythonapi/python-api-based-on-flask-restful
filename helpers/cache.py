from config import config

class Cache():
    def __init__(self):
        return base.Client((config['cache']['host'], config['cache']['port']))
