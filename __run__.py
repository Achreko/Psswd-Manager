from app import app
from routes import *
from models import clear_data

if __name__ == '__main__':
    #LATER ADD TO NGINX + GUNICORN IF ENOUGH TIME 
    clear_data()
    app.run(ssl_context=('cert/test.crt', 'cert/test.key'), debug=False)