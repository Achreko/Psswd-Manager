from app import app
from routes import *

if __name__ == '__main__':
    #LATER CHANGE TO NGINX + GUNICORN IF ENOUGH TIME 
    app.run(ssl_context=('cert/test.crt', 'cert/test.key'), debug=True )


