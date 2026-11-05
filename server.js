const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(express.json());
const ARCHIVO_TAREAS = path.join(__dirname, 'tareas.json');
const ARCHIVO_USUARIOS = path.join(__dirname, 'usuarios.json');

async function leerArchivo(archivo) {
    const contenido = await fs.readFile(archivo, 'utf8');
    return JSON.parse(contenido);
}

async function guardarArchivo(archivo, datos) {
    await fs.writeFile(
        archivo,
        JSON.stringify(datos, null, 2)
    );
}
const SECRET_KEY = process.env.JWT_SECRET;

app.post('/register', async (req, res, next) => {
    try {
        const { usuario, password } = req.body;

        if (!usuario || !password ||
            usuario.trim() === '' || password.length < 8) {
            return res.status(400).json({
                mensaje: 'Usuario y contraseña de mínimo 8 caracteres requeridos'
            });
        }

        const usuarios = await leerArchivo(ARCHIVO_USUARIOS);

        const existe = usuarios.find(
            u => u.usuario === usuario
        );

        if (existe) {
            return res.status(409).json({
                mensaje: 'El usuario ya existe'
            });
        }

        const hash = await bcrypt.hash(password, 10);

        const nuevoUsuario = {
            id: crypto.randomUUID(),
            usuario,
            password: hash
        };

        usuarios.push(nuevoUsuario);

        await guardarArchivo(ARCHIVO_USUARIOS, usuarios);

        res.status(201).json({
            mensaje: 'Usuario registrado correctamente'
        });

    } catch (error) {
        next(error);
    }
});
app.post('/login', async (req, res, next) => {
    try {
        const { usuario, password } = req.body;

        const usuarios = await leerArchivo(ARCHIVO_USUARIOS);

        const encontrado = usuarios.find(
            u => u.usuario === usuario
        );

        if (!encontrado) {
            return res.status(401).json({
                mensaje: 'Credenciales incorrectas'
            });
        }

        const valido = await bcrypt.compare(
            password,
            encontrado.password
        );

        if (!valido) {
            return res.status(401).json({
                mensaje: 'Credenciales incorrectas'
            });
        }

        const token = jwt.sign(
            { id: encontrado.id, usuario: encontrado.usuario },
            SECRET_KEY,
            { expiresIn: '1h' }
        );

        res.json({
            mensaje: 'Inicio de sesión exitoso',
            token
        });

    } catch (error) {
        next(error);
    }
});
function autenticarToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            mensaje: 'Se requiere un token de autenticación'
        });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, SECRET_KEY, (error, usuario) => {
        if (error) {
            return res.status(403).json({
                mensaje: 'Token inválido o expirado'
            });
        }

        req.user = usuario;
        next();
    });
}
app.get('/tareas', autenticarToken, async (req, res, next) => {
    try {
        const tareas = await leerArchivo(ARCHIVO_TAREAS);
        res.json(tareas);
    } catch (error) {
        next(error);
    }
});
app.post('/tareas', autenticarToken, async (req, res, next) => {
    try {
        const { titulo, descripcion } = req.body;

        if (
            typeof titulo !== 'string' ||
            typeof descripcion !== 'string' ||
            !titulo.trim() ||
            !descripcion.trim()
        ) {
            return res.status(400).json({
                mensaje: 'El título y la descripción son obligatorios'
            });
        }

        const tareas = await leerArchivo(ARCHIVO_TAREAS);

        const nuevaTarea = {
            id: crypto.randomUUID(),
            titulo: titulo.trim(),
            descripcion: descripcion.trim(),
            usuarioId: req.user.id,
            completada: false
        };

        tareas.push(nuevaTarea);

        await guardarArchivo(ARCHIVO_TAREAS, tareas);

        res.status(201).json({
            mensaje: 'Tarea creada correctamente',
            tarea: nuevaTarea
        });

    } catch (error) {
        next(error);
    }
});
app.put('/tareas/:id', autenticarToken, async (req, res, next) => {
    try {
        const tareas = await leerArchivo(ARCHIVO_TAREAS);

        const indice = tareas.findIndex(
            t => t.id === req.params.id &&
                 t.usuarioId === req.user.id
        );

        if (indice === -1) {
            return res.status(404).json({
                mensaje: 'Tarea no encontrada'
            });
        }

        const { titulo, descripcion, completada } = req.body;

        if (titulo !== undefined &&
            (typeof titulo !== 'string' || !titulo.trim())) {
            return res.status(400).json({
                mensaje: 'Título inválido'
            });
        }

        if (descripcion !== undefined &&
            (typeof descripcion !== 'string' || !descripcion.trim())) {
            return res.status(400).json({
                mensaje: 'Descripción inválida'
            });
        }

        if (completada !== undefined &&
            typeof completada !== 'boolean') {
            return res.status(400).json({
                mensaje: 'El estado completada debe ser booleano'
            });
        }

        if (titulo !== undefined) tareas[indice].titulo = titulo.trim();
        if (descripcion !== undefined) tareas[indice].descripcion = descripcion.trim();
        if (completada !== undefined) tareas[indice].completada = completada;

        await guardarArchivo(ARCHIVO_TAREAS, tareas);

        res.json({
            mensaje: 'Tarea actualizada',
            tarea: tareas[indice]
        });

    } catch (error) {
        next(error);
    }
});
app.delete('/tareas/:id', autenticarToken, async (req, res, next) => {
    try {
        const tareas = await leerArchivo(ARCHIVO_TAREAS);

        const nuevasTareas = tareas.filter(
            t => !(t.id === req.params.id &&
                   t.usuarioId === req.user.id)
        );

        if (nuevasTareas.length === tareas.length) {
            return res.status(404).json({
                mensaje: 'Tarea no encontrada'
            });
        }

        await guardarArchivo(ARCHIVO_TAREAS, nuevasTareas);

        res.json({
            mensaje: 'Tarea eliminada correctamente'
        });

    } catch (error) {
        next(error);
    }
});
// Ruta para solicitudes inexistentes
app.use((req, res) => {
    res.status(404).json({
        mensaje: 'Ruta no encontrada'
    });
});

// Middleware general de errores
app.use((err, req, res, next) => {
    console.error('Error:', err.stack);

    if (res.headersSent) {
        return next(err);
    }

    const status = err.status || 500;

    res.status(status).json({
        mensaje: status === 500
            ? 'Error interno del servidor'
            : err.message
    });
});
if (!SECRET_KEY) {
    throw new Error('Debes configurar JWT_SECRET');
}

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
