import base64
import requests
from twisted.internet import reactor
from twisted.web import proxy, http

# 1. PEGA AQUÍ TU ENLACE RAW DE GITHUB (donde tienes tus usuarios/keys)
# El formato dentro de tu keys.txt en GitHub debe ser: usuario:contraseña (uno por línea)
# Ejemplo en GitHub:
# yona:premium2026
# user2:clave99
URL_KEYS_GITHUB = "https://raw.githubusercontent.com/yonatona/mi-proxy-ff/refs/heads/main/keys.txt"

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
            
            # Descargar la lista de llaves actualizadas desde tu GitHub gratis
            response = requests.get(URL_KEYS_GITHUB, timeout=5)
            if response.status_code == 200:
                keys_validas = response.text.splitlines()
                
                # Verificar si las credenciales están en tu lista de GitHub
                if decoded in keys_validas:
                    # Credenciales correctas -> Permitir el tráfico de internet
                    return proxy.ProxyRequest.process(self)
            
            # Si no coincide o falla la conexión a GitHub, denegar acceso
            self.denyAccess()
            
        except Exception as e:
            print(f"Error en validación: {e}")
            self.denyAccess()

    def requestAuth(self):
        self.setResponseCode(401)
        self.setHeader(b'WWW-Authenticate', b'Basic realm="Proxy Privado - Introduce tu Key"')
        self.write(b"Se requiere una Key/Licencia valida para usar este proxy.")
        self.finish()

    def denyAccess(self):
        self.setResponseCode(403)
        self.write(b"Key incorrecta, vencida o no autorizada.")
        self.finish()

class SecureProxy(proxy.Proxy):
    requestFactory = SecureProxyRequest

class SecureProxyFactory(http.HTTPFactory):
    def buildProtocol(self, addr):
        return SecureProxy()

# Puerto donde escuchará el servidor
PORT = 8080
print(f"Servidor Proxy con Seguridad de Keys activo en el puerto {PORT}...")
reactor.listenTCP(PORT, SecureProxyFactory())
reactor.run()
