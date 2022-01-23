from app import app, clear_data
from routes import *

if __name__ == '__main__':
    #LATER CHANGE TO NGINX + GUNICORN IF ENOUGH TIME 
    clear_data()
    app.run(ssl_context=('cert/test.crt', 'cert/test.key'), debug=True )