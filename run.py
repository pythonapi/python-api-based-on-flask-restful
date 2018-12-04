from app import app

if __name__ == "__main__":        
    app.run(port=config['app']['port'], debug=config['app']['debug'])
