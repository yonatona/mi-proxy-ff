import base64
import requests
from twisted.internet import reactor
from twisted.web import proxy, http
from werkzeug.security import check_password_hash

# 1. ENLACE RAW DE GITHUB (Apunta a tu archivo claves.txt)
URL_KEYS_GITHUB = "https://raw.githubusercontent.com/yonatona/mi-proxy-ff/principal/claves.txt"

class SecureProxyRequest(proxy.ProxyRequest):
    def process(self):
        # Obtener el encabezado de autenticación enviado por el usuario
        auth_header = self.getHeader(b'Authorization')
        
        if not auth_header:
            self.requestAuth()
            return

        try:
            # Descifrar las credenciales enviadas (Formato: Basic base64)
            auth_type, encoded_credentials = auth_header.split(b' ', 1)
            decoded = base64.b64decode(encoded_credentials).decode('utf-8')
            
            # Descargar la lista de llaves actualizadas desde tu GitHub
            response = requests.get(URL_KEYS_GITHUB, timeout=5)
            if response.status_code == 200:
                keys_validas = response.text.splitlines()
            else:
                keys_validas = []

            # Verificar si las credenciales coinciden con algún hash seguro
            credenciales_validas = False
            for linea in keys_validas:
                if ":" in linea:
                    u_github, hash_github = linea.split(":", 1)
                    if ":" in decoded:
                        u_ingresado, pass_ingresado = decoded.split(":", 1)
                        if u_github.strip() == u_ingresado.strip() and check_password_hash(hash_github.strip(), pass_ingresado.strip()):
                            credenciales_validas = True
                            break

            if credenciales_validas:
                return proxy.ProxyRequest.process(self)
            else:
                self.denyAccess()

        except Exception as e:
            print(f"Error en validación: {e}")
            self.denyAccess()

    def requestAuth(self):
        self.setResponseCode(401)
        self.setHeader(b'WWW-Authenticate', b'Basic realm="Secure Proxy"')
        self.write(b"Se requiere una Key/Licencia valida.")
        self.finish()

    def denyAccess(self):
        self.setResponseCode(403)
        self.write(b"Key incorrecta, vencida o sin autorizacion.")
        self.finish()

class SecureProxy(proxy.Proxy):
    requestFactory = SecureProxyRequest

class SecureProxyFactory(http.HTTPFactory):
    def buildProtocol(self, addr):
        return SecureProxy()

if __name__ == "__main__":
    # El proxy correra localmente en el puerto 8080
    reactor.listenTCP(8080, SecureProxyFactory())
    print("Proxy seguro corriendo en el puerto 8080...")
    reactor.run()
