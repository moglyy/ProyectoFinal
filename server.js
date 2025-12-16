const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2');

// ==================== CONFIGURACIÓN ====================

// Configuración de la sesión
app.use(session({
  secret: 'tacosChiapasSecret2024',
  resave: false,
  saveUninitialized: false,
}));

app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configurar conexión a MySQL
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'trinidad',
  database: 'tacos_chiapass'
});

connection.connect(err => {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('✅ Conexión exitosa a MySQL - Base: tacos_chiapass');
});

// ==================== FUNCIÓN AUXILIAR ====================

function crearPaginaError(mensaje, enlaceRetorno) {
    return `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Error</title>
      <style>
        .error-container {
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
        }
        .error-message {
            background: #fee;
            color: #a84c94ff;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #e97ebcff;
            margin: 20px 0;
        }
        button {
            background: #97c1ddff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px;
        }
      </style>
    </head>
    <body>
      <div class="error-container">
        <h1>⚠️ Error</h1>
        <div class="error-message">
          <p>${mensaje}</p>
        </div>
        <button onclick="window.location.href='${enlaceRetorno}'">Volver</button>
      </div>
    </body>
    </html>
    `;
}

// ==================== AUTENTICACIÓN ====================

// REGISTRO (solo nombre, password y código)
app.post('/registro', (req, res) => {
    const { nombre, password, codigo_acceso } = req.body;

    // Validar campos
    if (!nombre || !password || !codigo_acceso) {
        return res.send(crearPaginaError('Todos los campos son obligatorios', '/registro.html'));
    }

    if (password.length < 4) {
        return res.send(crearPaginaError('La contraseña debe tener al menos 4 caracteres', '/registro.html'));
    }

    // Verificar código
    const queryCodigo = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
    
    connection.query(queryCodigo, [codigo_acceso.trim()], async (err, results) => {
        if (err) {
            return res.send(crearPaginaError('Error en la base de datos', '/registro.html'));
        }

        if (results.length === 0) {
            return res.send(crearPaginaError(
                'Código inválido. Los códigos válidos son:<br>' +
                '• CODIGO_ADMIN_TACOS (admin)<br>' +
                '• CODIGO_EMPLEADO_TACOS (empleado)<br>' +
                '• CODIGO_CLIENTE_TACOS (cliente)',
                '/registro.html'
            ));
        }

        const tipo_usuario = results[0].tipo_usuario;
        
        // Verificar si el nombre ya existe
        const checkUserQuery = 'SELECT id FROM usuarios WHERE nombre = ?';
        connection.query(checkUserQuery, [nombre], async (checkErr, checkResults) => {
            if (checkErr) {
                return res.send(crearPaginaError('Error al verificar usuario', '/registro.html'));
            }
            
            if (checkResults.length > 0) {
                return res.send(crearPaginaError('Este nombre de usuario ya está registrado', '/registro.html'));
            }

            try {
                // Encriptar contraseña
                const hashedPassword = await bcrypt.hash(password, 10);

                // Insertar usuario
                const insertUser = 'INSERT INTO usuarios (nombre, password_hash, tipo_usuario, compras_realizadas) VALUES (?, ?, ?, ?)';
                
                connection.query(insertUser, [nombre, hashedPassword, tipo_usuario, 0], (insertErr, result) => {
                    if (insertErr) {
                        return res.send(crearPaginaError('Error al registrar usuario', '/registro.html'));
                    }
                    
                    console.log(`✅ Usuario registrado: ${nombre} como ${tipo_usuario}`);
                    
                    // Página de éxito
                    let html = `
                    <html>
                    <head><link rel="stylesheet" href="/styles.css"><title>Registro Exitoso</title></head>
                    <body>
                        <div style="max-width: 500px; margin: 50px auto; padding: 20px; text-align: center;">
                            <h2 style="color: #27ae60;">✅ Registro Exitoso</h2>
                            <p><strong>Usuario:</strong> ${nombre}</p>
                            <p><strong>Tipo:</strong> ${tipo_usuario}</p>
                            <button onclick="window.location.href='/login.html'">Ir a Login</button>
                            <button onclick="window.location.href='/'">Ir al Inicio</button>
                        </div>
                    </body>
                    </html>
                    `;
                    
                    res.send(html);
                });
            } catch (error) {
                return res.send(crearPaginaError('Error en el registro', '/registro.html'));
            }
        });
    });
});

// LOGIN (con nombre de usuario)
app.post('/login', (req, res) => {
    const { nombre_usuario, password } = req.body;
    const query = 'SELECT * FROM usuarios WHERE nombre = ?';
    
    connection.query(query, [nombre_usuario], async (err, results) => { 
        
        if (err) {
            return res.send(crearPaginaError('Error al obtener el usuario', '/login.html'));
        }

        if (results.length === 0) {
            return res.send(crearPaginaError('Usuario no encontrado', '/login.html'));
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        
        if (!isPasswordValid) {
            return res.send(crearPaginaError('Contraseña incorrecta', '/login.html'));
        }

        // Guardar en sesión
        req.session.user = {
            id: user.id,
            nombre: user.nombre,
            tipo_usuario: user.tipo_usuario,
            compras_realizadas: user.compras_realizadas || 0
        };

        res.redirect('/');
    });
});

// CERRAR SESIÓN
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// ==================== MIDDLEWARES ====================

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

function allowRoles(roles = []) {
  return (req, res, next) => {
    if (req.session.user && roles.includes(req.session.user.tipo_usuario)) {
      next();
    } else {
      res.send(crearPaginaError('Acceso denegado. No tienes permisos suficientes', '/'));
    }
  };
}

// ==================== RUTAS DE USUARIO ====================

// Obtener información del usuario
app.get('/user-info', requireLogin, (req, res) => {
    res.json({
        nombre: req.session.user.nombre,
        compras_realizadas: req.session.user.compras_realizadas,
        tipo_usuario: req.session.user.tipo_usuario
    });
});

// Ver menú
app.get('/menu', requireLogin, (req, res) => {
    const query = 'SELECT * FROM tacos WHERE disponible = 1';
    
    connection.query(query, (err, results) => {
        if (err) {
            return res.send(crearPaginaError('Error al cargar el menú', '/'));
        }

        let html = `
        <html>
        <head><link rel="stylesheet" href="/styles.css"><title>Menú</title></head>
        <body>
            <h1>🌮 Menú de Tacos Chiapas</h1>
            <p>Bienvenido, ${req.session.user.nombre}!</p>
        `;

        if (results.length === 0) {
            html += '<p>No hay tacos disponibles en este momento.</p>';
        } else {
            results.forEach(taco => {
                html += `
                <div style="border:1px solid #ddd; padding:10px; margin:10px;">
                    <h3>${taco.nombre} - $${taco.precio}</h3>
                    <p>${taco.descripcion || ''}</p>
                </div>
                `;
            });
        }

        html += `
            <button onclick="window.location.href='/descargar-menu-txt'" style="background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; margin: 10px;">📥 Descargar Menú (TXT)</button>
            <button onclick="window.location.href='/'">Volver al inicio</button>
        </body>
        </html>
        `;
        
        res.send(html);
    });
});

// Descargar menú en TXT
app.get('/descargar-menu-txt', requireLogin, (req, res) => {
    const query = 'SELECT * FROM tacos WHERE disponible = 1';
    
    connection.query(query, (err, results) => {
        if (err) {
            return res.status(500).send('Error al generar el archivo');
        }

        let txtContent = '🌮 MENÚ DE TACOS CHIAPAS 🌮\n\n';
        txtContent += `Fecha: ${new Date().toLocaleDateString()}\n`;
        txtContent += `Usuario: ${req.session.user.nombre}\n\n`;
        txtContent += '================================\n\n';

        if (results.length === 0) {
            txtContent += 'No hay tacos disponibles en este momento.\n';
        } else {
            results.forEach(taco => {
                txtContent += `${taco.nombre}\n`;
                txtContent += `Precio: $${taco.precio}\n`;
                if (taco.descripcion) {
                    txtContent += `Descripción: ${taco.descripcion}\n`;
                }
                txtContent += '\n--------------------------------\n\n';
            });
        }

        txtContent += '¡Gracias por visitar Tacos Chiapas!\n';
        txtContent += 'Ave. ITR Tijuana s/n, Mesa de Otay, C.P. 22430\n';
        txtContent += 'Horarios: Lunes a Domingo 10:00 AM - 10:00 PM\n';

        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', 'attachment; filename="menu_tacos_chiapas.txt"');
        res.send(txtContent);
    });
});

// Perfil de cliente frecuente
app.get('/mi-perfil', requireLogin, (req, res) => {
    const user = req.session.user;
    const comprasFaltantes = 8 - (user.compras_realizadas % 8);
    const tieneRecompensa = user.compras_realizadas >= 8;

    let html = `
    <html>
    <head><link rel="stylesheet" href="/styles.css"><title>Mi Perfil</title></head>
    <body>
        <h1>⭐ Mi Perfil</h1>
        <p><strong>Usuario:</strong> ${user.nombre}</p>
        <p><strong>Compras realizadas:</strong> ${user.compras_realizadas}</p>
        <p><strong>Tipo de cuenta:</strong> ${user.tipo_usuario}</p>
        
        <h2>Programa de recompensas</h2>
        <p>Compras: ${user.compras_realizadas % 8}/8</p>
        <p>Faltan ${comprasFaltantes} compras para tu combo gratis</p>
    `;

    if (tieneRecompensa) {
        html += `
        <div style="background:#2ecc71; color:white; padding:15px; margin:20px 0;">
            <h3>🎉 ¡TIENES UN COMBO GRATIS! 🎉</h3>
            <p>Muestra este mensaje al personal para reclamar tu recompensa.</p>
        </div>
        `;
    }

    res.send(html);
});
// ==================== MODIFICACIÓN: RUTA PARA REGISTRAR COMPRAS (solo admin/empleado) ====================

// Ruta para que admin/empleado registre compras a usuarios
app.get('/registrar-compra-usuario', requireLogin, allowRoles(['admin', 'empleado']), (req, res) => {
    // Obtener lista de usuarios (clientes)
    const queryUsuarios = 'SELECT id, nombre, compras_realizadas FROM usuarios WHERE tipo_usuario = "cliente"';
    
    connection.query(queryUsuarios, (err, usuarios) => {
        if (err) {
            return res.send(crearPaginaError('Error al cargar usuarios', '/'));
        }

        let html = `
        <html>
        <head>
            <link rel="stylesheet" href="/styles.css">
            <title>Registrar Compra a Cliente</title>
            <style>
                .user-card {
                    border: 1px solid #ddd;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                    background: #f9f9f9;
                }
                .compras-info {
                    color: #a98cdfff;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <h1>💰 Registrar Compra a Cliente</h1>
            <p><strong>Usuario actual:</strong> ${req.session.user.nombre} (${req.session.user.tipo_usuario})</p>
            
            <div style="background: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p><strong>Instrucciones:</strong></p>
                <p>1. Selecciona un cliente de la lista</p>
                <p>2. Ingresa el monto de la compra</p>
                <p>3. Solo compras mayores a $100 cuentan para el programa de recompensas</p>
            </div>
        `;

        if (usuarios.length === 0) {
            html += '<p>No hay clientes registrados.</p>';
        } else {
            usuarios.forEach(usuario => {
                html += `
                <div class="user-card">
                    <h3>👤 ${usuario.nombre}</h3>
                    <p>Compras acumuladas: <span class="compras-info">${usuario.compras_realizadas}</span></p>
                    <p>Faltan: <strong>${8 - (usuario.compras_realizadas % 8)}</strong> compras para su próximo combo gratis</p>
                    
                    <form action="/procesar-compra-cliente" method="POST">
                        <input type="hidden" name="usuario_id" value="${usuario.id}">
                        <input type="hidden" name="usuario_nombre" value="${usuario.nombre}">
                        
                        <label for="monto_${usuario.id}">Monto de la compra:</label>
                        <input type="number" id="monto_${usuario.id}" name="monto" min="1" step="0.01" placeholder="Ej: 150.00" required>
                        
                        <button type="submit" style="background: #87bfecff;">Registrar Compra</button>
                    </form>
                </div>
                `;
            });
        }

        html += `
            <br>
            <button onclick="window.location.href='/'">Volver al inicio</button>
            ${req.session.user.tipo_usuario === 'admin' ? '<button onclick="window.location.href=\'/admin-panel\'">Ir al Panel Admin</button>' : ''}
            ${req.session.user.tipo_usuario === 'empleado' ? '<button onclick="window.location.href=\'/empleado-panel\'">Ir al Panel Empleado</button>' : ''}
        </body>
        </html>
        `;
        
        res.send(html);
    });
});

// Procesar la compra del cliente
app.post('/procesar-compra-cliente', requireLogin, allowRoles(['admin', 'empleado']), (req, res) => {
    const { usuario_id, usuario_nombre, monto } = req.body;
    const montoFloat = parseFloat(monto);
    
    if (montoFloat >= 100) {
        // Registrar la compra (incrementar contador)
        const query = 'UPDATE usuarios SET compras_realizadas = compras_realizadas + 1 WHERE id = ?';
        
        connection.query(query, [usuario_id], (err, result) => {
            if (err) {
                return res.send(crearPaginaError('Error al registrar compra', '/registrar-compra-usuario'));
            }
            
            // Obtener el nuevo estado del usuario
            const queryEstado = 'SELECT compras_realizadas FROM usuarios WHERE id = ?';
            connection.query(queryEstado, [usuario_id], (errEstado, resultados) => {
                if (errEstado) {
                    return res.send(crearPaginaError('Error al obtener estado del usuario', '/registrar-compra-usuario'));
                }
                
                const nuevasCompras = resultados[0].compras_realizadas;
                const tieneRecompensa = nuevasCompras >= 8 && nuevasCompras % 8 === 0;
                
                // Página de éxito
                let html = `
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    <title>Compra Registrada</title>
                    <style>
                        .success-card {
                            background: linear-gradient(to right, #8e95ebff, #2ecc71);
                            color: white;
                            padding: 30px;
                            border-radius: 10px;
                            margin: 30px 0;
                            text-align: center;
                        }
                        .info-card {
                            background: #f8f9fa;
                            padding: 20px;
                            border-radius: 5px;
                            margin: 20px 0;
                            border-left: 4px solid #3498db;
                        }
                    </style>
                </head>
                <body>
                    <div style="max-width: 600px; margin: 50px auto; padding: 20px;">
                        <div class="success-card">
                            <h2>✅ Compra Registrada Exitosamente</h2>
                            <p>Compra de $${monto} MXN registrada para el cliente</p>
                        </div>
                        
                        <div class="info-card">
                            <h3>📋 Información de la compra:</h3>
                            <p><strong>Cliente:</strong> ${usuario_nombre}</p>
                            <p><strong>Monto:</strong> $${monto} MXN</p>
                            <p><strong>Registrado por:</strong> ${req.session.user.nombre} (${req.session.user.tipo_usuario})</p>
                            <p><strong>Total de compras del cliente:</strong> ${nuevasCompras}</p>
                            <p><strong>Próxima recompensa en:</strong> ${8 - (nuevasCompras % 8)} compras</p>
                        </div>
                `;
                
                if (tieneRecompensa) {
                    html += `
                        <div style="background: #c48cf1ff; color: white; padding: 20px; border-radius: 5px; margin: 20px 0;">
                            <h3>🎉 ¡EL CLIENTE HA GANADO UN COMBO GRATIS! 🎉</h3>
                            <p>El cliente ${usuario_nombre} ha acumulado 8 compras y merece su recompensa.</p>
                            <p><strong>Notificar al cliente y entregar su combo gratis.</strong></p>
                        </div>
                    `;
                }
                
                html += `
                        <div style="margin: 30px 0; display: flex; gap: 15px; justify-content: center;">
                            <button onclick="window.location.href='/registrar-compra-usuario'" 
                                    style="background: #3498db; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer;">
                                📝 Registrar otra compra
                            </button>
                            <button onclick="window.location.href='/'"
                                    style="background: #95a5a6; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer;">
                                🏠 Ir al inicio
                            </button>
                        </div>
                    </div>
                </body>
                </html>
                `;
                
                res.send(html);
            });
        });
    } else {
        res.send(crearPaginaError(
            `El monto debe ser mayor o igual a $100 MXN para contar en el programa de recompensas.<br>
            <strong>Monto ingresado:</strong> $${monto} MXN<br><br>
            Si la compra es menor a $100, no se registra en el sistema de cliente frecuente.`,
            '/registrar-compra-usuario'
        ));
    }
});

// ==================== NUEVA RUTA: GESTIONAR EMPLEADOS (solo admin) ====================

// Panel de gestión de empleados
app.get('/admin/gestionar-empleados', requireLogin, allowRoles(['admin']), (req, res) => {
    // Obtener todos los empleados
    const queryEmpleados = 'SELECT id, nombre, tipo_usuario, fecha_registro FROM usuarios WHERE tipo_usuario = "empleado" ORDER BY fecha_registro DESC';
    
    connection.query(queryEmpleados, (err, empleados) => {
        if (err) {
            return res.send(crearPaginaError('Error al cargar empleados', '/admin-panel'));
        }

        let html = `
        <html>
        <head>
            <link rel="stylesheet" href="/styles.css">
            <title>Gestión de Empleados</title>
            <style>
                .employee-card {
                    border: 1px solid #ddd;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                    background: #f8f9fa;
                }
                .employee-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .badge {
                    background: #83a1f1ff;
                    color: white;
                    padding: 5px 10px;
                    border-radius: 15px;
                    font-size: 0.8em;
                }
                .actions {
                    margin-top: 10px;
                }
                .danger-btn {
                    background: #d93ce7ff;
                }
            </style>
        </head>
        <body>
            <h1>👥 Gestión de Empleados</h1>
            <p><strong>Administrador:</strong> ${req.session.user.nombre}</p>
            
            <div style="background: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3>📋 Información importante:</h3>
                <p>• Solo los administradores pueden gestionar empleados</p>
                <p>• Los empleados tienen acceso al panel de empleado</p>
                <p>• Pueden registrar compras de clientes</p>
                <p>• No tienen acceso al panel de administración</p>
            </div>
            
            <h2>➕ Agregar nuevo empleado:</h2>
            <div style="background: #f0f8ff; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <p>Para agregar un nuevo empleado:</p>
                <ol>
                    <li>Comparte el código: <code><strong>CODIGO_EMPLEADO_TACOS</strong></code></li>
                    <li>El empleado debe registrarse usando ese código</li>
                    <li>Aparecerá automáticamente en esta lista</li>
                </ol>
                <p><strong>Código actual para empleados:</strong> <code style="background: #2ecc71; color: white; padding: 5px 10px; border-radius: 3px;">CODIGO_EMPLEADO_TACOS</code></p>
            </div>
            
            <h2>📋 Lista de empleados registrados:</h2>
        `;

        if (empleados.length === 0) {
            html += '<p>No hay empleados registrados aún.</p>';
        } else {
            empleados.forEach(empleado => {
                const fecha = new Date(empleado.fecha_registro).toLocaleDateString('es-MX');
                
                html += `
                <div class="employee-card">
                    <div class="employee-header">
                        <h3>👤 ${empleado.nombre}</h3>
                        <span class="badge">EMPLEADO</span>
                    </div>
                    <p><strong>ID:</strong> ${empleado.id}</p>
                    <p><strong>Fecha de registro:</strong> ${fecha}</p>
                    
                    <div class="actions">
                        <button onclick="window.location.href='/admin/ver-compras-empleado/${empleado.id}'" 
                                style="background: #3498db; margin-right: 10px;">
                            📊 Ver actividad
                        </button>
                        <form action="/admin/eliminar-empleado" method="POST" style="display:inline;">
                            <input type="hidden" name="empleado_id" value="${empleado.id}">
                            <input type="hidden" name="empleado_nombre" value="${empleado.nombre}">
                            <button type="submit" class="danger-btn" 
                                    onclick="return confirm('¿Estás seguro de eliminar al empleado ${empleado.nombre}?')">
                                🗑️ Eliminar
                            </button>
                        </form>
                    </div>
                </div>
                `;
            });
        }

        html += `
            <h2>📊 Estadísticas:</h2>
            <div style="display: flex; gap: 20px; margin: 20px 0;">
                <div style="flex: 1; background: #3498db; color: white; padding: 20px; border-radius: 5px; text-align: center;">
                    <h3>Total empleados</h3>
                    <p style="font-size: 2em;">${empleados.length}</p>
                </div>
                <div style="flex: 1; background: #ba8be6ff; color: white; padding: 20px; border-radius: 5px; text-align: center;">
                    <h3>Código activo</h3>
                    <p style="font-size: 1.2em;">CODIGO_EMPLEADO_TACOS</p>
                </div>
            </div>
            
            <div style="margin: 30px 0;">
                <button onclick="window.location.href='/admin-panel'" 
                        style="background: #3498db; padding: 12px 24px; margin-right: 15px;">
                    ⚙️ Volver al Panel Admin
                </button>
                <button onclick="window.location.href='/registrar-compra-usuario'"
                        style="background: #ba8be6ff; padding: 12px 24px;">
                    💰 Registrar compras
                </button>
                <button onclick="window.location.href='/'"
                        style="background: #95a5a6; padding: 12px 24px;">
                    🏠 Ir al inicio
                </button>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    });
});

// Ver actividad de un empleado específico
app.get('/admin/ver-compras-empleado/:id', requireLogin, allowRoles(['admin']), (req, res) => {
    const empleadoId = req.params.id;
    
    // Obtener información del empleado
    const queryEmpleado = 'SELECT nombre FROM usuarios WHERE id = ? AND tipo_usuario = "empleado"';
    
    connection.query(queryEmpleado, [empleadoId], (err, results) => {
        if (err || results.length === 0) {
            return res.send(crearPaginaError('Empleado no encontrado', '/admin/gestionar-empleados'));
        }
        
        const empleadoNombre = results[0].nombre;
        
        // NOTA: Para un sistema más completo, necesitarías una tabla de transacciones
        // Por ahora mostraremos información básica
        
        let html = `
        <html>
        <head>
            <link rel="stylesheet" href="/styles.css">
            <title>Actividad de Empleado</title>
        </head>
        <body>
            <div style="max-width: 800px; margin: 50px auto; padding: 20px;">
                <h1>📊 Actividad del Empleado</h1>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                    <h2>👤 ${empleadoNombre}</h2>
                    <p><strong>ID del empleado:</strong> ${empleadoId}</p>
                    <p><strong>Rol:</strong> Empleado</p>
                </div>
                
                <div style="background: #e8f4f8; padding: 20px; border-radius: 5px; margin: 20px 0;">
                    <h3>📋 Información del sistema:</h3>
                    <p>Para un sistema completo, se recomienda crear una tabla de transacciones que registre:</p>
                    <ul>
                        <li>Compras registradas por cada empleado</li>
                        <li>Fecha y hora de cada registro</li>
                        <li>Monto de cada compra</li>
                        <li>Cliente atendido</li>
                    </ul>
                    <p><strong>Tabla sugerida:</strong></p>
                    <pre style="background: #2c3e50; color: white; padding: 15px; border-radius: 5px;">
CREATE TABLE transacciones (
    id INT PRIMARY KEY AUTO_INCREMENT,
    empleado_id INT,
    cliente_id INT,
    monto DECIMAL(10,2),
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (empleado_id) REFERENCES usuarios(id),
    FOREIGN KEY (cliente_id) REFERENCES usuarios(id)
);</pre>
                </div>
                
                <div style="margin: 30px 0;">
                    <button onclick="window.location.href='/admin/gestionar-empleados'" 
                            style="background: #3498db; padding: 12px 24px;">
                        ↩️ Volver a gestión de empleados
                    </button>
                    <button onclick="window.location.href='/admin-panel'"
                            style="background: #95a5a6; padding: 12px 24px;">
                        ⚙️ Panel Admin
                    </button>
                </div>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    });
});

// Eliminar empleado
app.post('/admin/eliminar-empleado', requireLogin, allowRoles(['admin']), (req, res) => {
    const { empleado_id, empleado_nombre } = req.body;
    
    // No permitir eliminarse a sí mismo
    if (parseInt(empleado_id) === req.session.user.id) {
        return res.send(crearPaginaError('No puedes eliminarte a ti mismo', '/admin/gestionar-empleados'));
    }
    
    const query = 'DELETE FROM usuarios WHERE id = ? AND tipo_usuario = "empleado"';
    
    connection.query(query, [empleado_id], (err, result) => {
        if (err) {
            return res.send(crearPaginaError('Error al eliminar empleado', '/admin/gestionar-empleados'));
        }
        
        if (result.affectedRows === 0) {
            return res.send(crearPaginaError('Empleado no encontrado o no es empleado', '/admin/gestionar-empleados'));
        }
        
        console.log(`🗑️ Empleado eliminado: ${empleado_nombre} (ID: ${empleado_id}) por admin: ${req.session.user.nombre}`);
        
        // Página de confirmación
        let html = `
        <html>
        <head>
            <link rel="stylesheet" href="/styles.css">
            <title>Empleado Eliminado</title>
        </head>
        <body>
            <div style="max-width: 600px; margin: 100px auto; padding: 20px; text-align: center;">
                <h2 style="color: #ba8be6ff;">✅ Empleado Eliminado Exitosamente</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 30px 0;">
                    <p><strong>Empleado eliminado:</strong> ${empleado_nombre}</p>
                    <p><strong>ID:</strong> ${empleado_id}</p>
                    <p><strong>Eliminado por:</strong> ${req.session.user.nombre} (Admin)</p>
                    <p><strong>Fecha:</strong> ${new Date().toLocaleString('es-MX')}</p>
                </div>
                
                <p>El empleado ya no tendrá acceso al sistema.</p>
                
                <div style="margin: 30px 0;">
                    <button onclick="window.location.href='/admin/gestionar-empleados'" 
                            style="background: #3498db; padding: 12px 24px; margin-right: 15px;">
                        ↩️ Volver a gestión de empleados
                    </button>
                    <button onclick="window.location.href='/admin-panel'"
                            style="background: #95a5a6; padding: 12px 24px;">
                        ⚙️ Panel Admin
                    </button>
                </div>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    });
});

// ==================== MODIFICAR EL PANEL DE ADMIN ====================

// Agregar el enlace a gestión de empleados en el panel admin
// Busca en tu server.js la ruta /admin-panel y agrega esto:

app.get('/admin-panel', requireLogin, allowRoles(['admin']), (req, res) => {
    let html = `
    <html>
    <head><link rel="stylesheet" href="/styles.css"><title>Panel Admin</title></head>
    <body>
        <h1>⚙️ Panel de Administración</h1>
        <p>Bienvenido, <strong>${req.session.user.nombre}</strong> (Administrador)</p>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0;">
            <div style="background: #3498db; color: white; padding: 20px; border-radius: 10px; text-align: center;">
                <h3>👥 Empleados</h3>
                <p>Gestiona el personal</p>
                <button onclick="window.location.href='/admin/gestionar-empleados'" 
                        style="background: white; color: #3498db; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
                    Gestionar
                </button>
            </div>
            
            <div style="background: #ba8be6ff; color: white; padding: 20px; border-radius: 10px; text-align: center;">
                <h3>🌮 Tacos</h3>
                <p>Administra el menú</p>
                <button onclick="window.location.href='/admin/gestionar-tacos'" 
                        style="background: white; color: #ba8be6ff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
                    Gestionar
                </button>
            </div>
            
            <div style="background: #9b59b6; color: white; padding: 20px; border-radius: 10px; text-align: center;">
                <h3>👤 Usuarios</h3>
                <p>Ver todos los usuarios</p>
                <button onclick="window.location.href='/admin/ver-usuarios'" 
                        style="background: white; color: #9b59b6; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
                    Ver
                </button>
            </div>
            
            <div style="background: #f087d9ff; color: white; padding: 20px; border-radius: 10px; text-align: center;">
                <h3>💰 Compras</h3>
                <p>Registrar compras a clientes</p>
                <button onclick="window.location.href='/registrar-compra-usuario'" 
                        style="background: white; color: #ab5eebff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
                    Registrar
                </button>
            </div>
        </div>
        
        <button onclick="window.location.href='/'">🏠 Volver al inicio</button>
    </body>
    </html>
    `;
    
    res.send(html);
});

// ==================== MODIFICAR EL PANEL DE EMPLEADO ====================

// Agregar el enlace a registrar compras en el panel de empleado
app.get('/empleado-panel', requireLogin, allowRoles(['empleado', 'admin']), (req, res) => {
    let html = `
    <html>
    <head><link rel="stylesheet" href="/styles.css"><title>Panel Empleado</title></head>
    <body>
        <h1>👨‍🍳 Panel de Empleado</h1>
        <p>Bienvenido, <strong>${req.session.user.nombre}</strong> (${req.session.user.tipo_usuario})</p>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0;">
            <div style="background: #eb96e4ff; color: white; padding: 20px; border-radius: 10px; text-align: center;">
                <h3>💰 Registrar compras</h3>
                <p>Registra compras de clientes</p>
                <button onclick="window.location.href='/registrar-compra-usuario'" 
                        style="background: white; color: #eb96e4ff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
                    Registrar
                </button>
            </div>
            
            <div style="background: #3498db; color: white; padding: 20px; border-radius: 10px; text-align: center;">
                <h3>🌮 Ver menú</h3>
                <p>Consulta el menú completo</p>
                <button onclick="window.location.href='/menu'" 
                        style="background: white; color: #3498db; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
                    Ver menú
                </button>
            </div>
            
            <div style="background: #e75fe0ff; color: white; padding: 20px; border-radius: 10px; text-align: center;">
                <h3>⭐ Mi perfil</h3>
                <p>Ver mi perfil de empleado</p>
                <button onclick="window.location.href='/mi-perfil'" 
                        style="background: white; color: #a783e0ff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
                    Ver perfil
                </button>
            </div>
        </div>
        
        <button onclick="window.location.href='/'">🏠 Volver al inicio</button>
    </body>
    </html>
    `;
    
    res.send(html);
});

// ==================== RUTAS DE ADMINISTRADOR ====================

// Panel de administración
app.get('/admin-panel', requireLogin, allowRoles(['admin']), (req, res) => {
    let html = `
    <html>
    <head><link rel="stylesheet" href="/styles.css"><title>Panel Admin</title></head>
    <body>
        <h1>⚙️ Panel de Administración</h1>
        <h3>Opciones:</h3>
        <ul>
            <li><a href="/admin/gestionar-tacos">Gestionar Tacos</a></li>
            <li><a href="/admin/ver-usuarios">Ver Usuarios</a></li>
        </ul>
        <button onclick="window.location.href='/'">Volver al inicio</button>
    </body>
    </html>
    `;
    
    res.send(html);
});

// Gestionar tacos (simplificado)
app.get('/admin/gestionar-tacos', requireLogin, allowRoles(['admin']), (req, res) => {
    const query = 'SELECT * FROM tacos';
    
    connection.query(query, (err, results) => {
        if (err) {
            return res.send(crearPaginaError('Error al cargar tacos', '/admin-panel'));
        }

        let html = `
        <html>
        <head><link rel="stylesheet" href="/styles.css"><title>Gestionar Tacos</title></head>
        <body>
            <h1>Gestionar Tacos</h1>
            
            <h2>Agregar nuevo taco:</h2>
            <form action="/admin/agregar-taco" method="POST">
                <input type="text" name="nombre" placeholder="Nombre" required>
                <input type="number" name="precio" placeholder="Precio" step="0.01" required>
                <button type="submit">Agregar</button>
            </form>
            
            <h2>Tacos existentes:</h2>
        `;

        results.forEach(taco => {
            html += `
            <div style="border:1px solid #ddd; padding:10px; margin:5px;">
                ${taco.nombre} - $${taco.precio}
                <form action="/admin/eliminar-taco" method="POST" style="display:inline;">
                    <input type="hidden" name="taco_id" value="${taco.id}">
                    <button type="submit">Eliminar</button>
                </form>
            </div>
            `;
        });

        html += `
            <br>
            <button onclick="window.location.href='/admin-panel'">Volver al panel</button>
        </body>
        </html>
        `;
        
        res.send(html);
    });
});

// Agregar taco
app.post('/admin/agregar-taco', requireLogin, allowRoles(['admin']), (req, res) => {
    const { nombre, precio } = req.body;
    
    const query = 'INSERT INTO tacos (nombre, precio, disponible) VALUES (?, ?, 1)';
    
    connection.query(query, [nombre, precio], (err, result) => {
        if (err) {
            return res.send(crearPaginaError('Error al agregar taco', '/admin/gestionar-tacos'));
        }
        
        res.redirect('/admin/gestionar-tacos');
    });
});

// Eliminar taco
app.post('/admin/eliminar-taco', requireLogin, allowRoles(['admin']), (req, res) => {
    const { taco_id } = req.body;
    
    const query = 'DELETE FROM tacos WHERE id = ?';
    
    connection.query(query, [taco_id], (err, result) => {
        if (err) {
            return res.send(crearPaginaError('Error al eliminar taco', '/admin/gestionar-tacos'));
        }
        
        res.redirect('/admin/gestionar-tacos');
    });
});

// Ver usuarios
app.get('/admin/ver-usuarios', requireLogin, allowRoles(['admin']), (req, res) => {
    const query = 'SELECT id, nombre, tipo_usuario, compras_realizadas FROM usuarios';
    
    connection.query(query, (err, results) => {
        if (err) {
            return res.send(crearPaginaError('Error al cargar usuarios', '/admin-panel'));
        }

        let html = `
        <html>
        <head><link rel="stylesheet" href="/styles.css"><title>Usuarios</title></head>
        <body>
            <h1>Usuarios Registrados</h1>
            <table border="1" style="width:100%; border-collapse:collapse;">
                <tr>
                    <th>ID</th>
                    <th>Nombre</th>
                    <th>Tipo</th>
                    <th>Compras</th>
                </tr>
        `;

        results.forEach(user => {
            html += `
                <tr>
                    <td>${user.id}</td>
                    <td>${user.nombre}</td>
                    <td>${user.tipo_usuario}</td>
                    <td>${user.compras_realizadas}</td>
                </tr>
            `;
        });

        html += `
            </table>
            <br>
            <button onclick="window.location.href='/admin-panel'">Volver al panel</button>
        </body>
        </html>
        `;
        
        res.send(html);
    });
});

// ==================== RUTAS DE EMPLEADO ====================

// Panel de empleado
app.get('/empleado-panel', requireLogin, allowRoles(['empleado', 'admin']), (req, res) => {
    let html = `
    <html>
    <head><link rel="stylesheet" href="/styles.css"><title>Panel Empleado</title></head>
    <body>
        <h1>👨‍🍳 Panel de Empleado</h1>
        <p>Bienvenido, ${req.session.user.nombre}!</p>
        <button onclick="window.location.href='/menu'">Ver Menú</button>
        <button onclick="window.location.href='/'">Volver al inicio</button>
    </body>
    </html>
    `;
    
    res.send(html);
});

// ==================== RUTAS PÚBLICAS ====================

// Información del establecimiento
app.get('/informacion', (req, res) => {
    let html = `
    <html>
    <head><link rel="stylesheet" href="/styles.css"><title>Información</title></head>
    <body>
        <h1>🏪 Tacos Chiapas</h1>
        <p><strong>Horario:</strong> 10:00 AM - 10:00 PM</p>
        <p><strong>Ubicación:</strong> Ave. ITR Tijuana s/n, Mesa de Otay</p>
        <p><strong>Promoción:</strong> Martes y Jueves 2x1 en tacos al pastor</p>
        <button onclick="window.location.href='/'">Volver al inicio</button>
    </body>
    </html>
    `;
    
    res.send(html);
});

// Tipo de usuario (para el navbar)
app.get('/tipo-usuario', requireLogin, (req, res) => {
    res.json({ tipo_usuario: req.session.user.tipo_usuario });
});

// ==================== ARCHIVOS ESTÁTICOS ====================

app.use(express.static(path.join(__dirname, 'public')));

// Ruta principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== INICIAR SERVIDOR ====================

app.listen(3000, () => {
    console.log('🚀 Servidor de Tacos Chiapas corriendo en: http://localhost:3000');
    console.log('📊 Base de datos: tacos_chiapass');
    console.log('👤 Usuarios: nombre + contraseña + código');
});

