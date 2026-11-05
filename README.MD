# CryptoLab — Historia de la criptografía

Aplicación web en PHP para aprender y probar tres técnicas criptográficas clásicas:

- **Escítala:** cifrado y descifrado por transposición.
- **César:** cifrado y descifrado con desplazamiento de 0 a 25.
- **Al-Kindi:** análisis de frecuencia de letras.

Las operaciones se guardan en MySQL y se muestran en el historial.

## Requisitos

- PHP 8.0 o posterior con las extensiones `PDO` y `pdo_mysql`.
- MySQL iniciado desde Laragon.

## Ejecutar localmente

1. Inicia MySQL desde Laragon.
2. Abre una terminal en esta carpeta.
3. Si la contraseña, el usuario o el puerto de MySQL son distintos de los valores por defecto, agrega las variables de `.env.example` a tu archivo `.env` local y edita los valores. Conserva cualquier otra configuración que ya tengas en ese archivo. No publiques `.env`.
4. Inicia el servidor PHP:

   ```powershell
   php -S 127.0.0.1:8000
   ```

   Si PowerShell no encuentra `php`, usa la ruta de PHP instalada en tu equipo, por ejemplo:

   ```powershell
   & 'C:\xampp\php\php.exe' -S 127.0.0.1:8000
   ```

5. Abre <http://127.0.0.1:8000>.

La aplicación crea automáticamente la base de datos `cryptonetdb` y la tabla `historial_criptografia`. La configuración predeterminada es `127.0.0.1:3306`, usuario `root` y contraseña vacía.

El servidor integrado de PHP es para desarrollo local, no para publicar la aplicación en producción.

## Consulta del historial

```sql
USE cryptonetdb;

SELECT
    id,
    algoritmo,
    operacion,
    texto_original,
    texto_resultado,
    clave,
    fecha_operacion
FROM historial_criptografia
ORDER BY fecha_operacion DESC, id DESC
LIMIT 100;
```

## Subir a GitHub

Desde la raíz del repositorio:

```powershell
git status --short
git add "Criptografia(Visual Code)/index.php" "Criptografia(Visual Code)/README.MD" "Criptografia(Visual Code)/.gitignore" "Criptografia(Visual Code)/.env.example"
git diff --cached --check
git diff --cached
```

Antes de confirmar, verifica que `.env`, contraseñas y otros archivos privados no aparezcan en los cambios preparados.
