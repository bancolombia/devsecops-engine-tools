# Session manager

Uso de la sesión envuelta en la clase personalizada
    session = SessionManager()

Ejemplo de solicitud utilizando la sesión
    response = session.get('https://www.example.com')

Realizar más solicitudes utilizando la misma sesión
    response2 = session.post('https://www.example.com/submit', data={'key': 'value'})