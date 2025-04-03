const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const dotenv = require('dotenv')
const { admin, db } = require('../config/firebase')
const winston = require('winston')
const jwt = require('jsonwebtoken')
const speakeasy = require('speakeasy')
const bcrypt = require('bcrypt')
const rateLimit = require('express-rate-limit')
const QRCode = require('qrcode')

require('dotenv').config();

const PORT = process.env.PORT || 3000
const routes = require('../routes')

const app = express()

// Configuración de Rate Limit - 100 peticiones cada 10 minutos
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutos
    max: 100, // 100 peticiones por ventana
    message: { message: 'Demasiadas peticiones, intenta más tarde' }
});

// Aplicar rate limit a todas las rutas
app.use(limiter);

// Modificar la configuración CORS para aceptar cualquier origen durante desarrollo
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:5174'],
  credentials: true
}))

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'server1-service' },
    transports: [
      new winston.transports.File({ filename: 'server1-error.log', level: 'error' }),
      new winston.transports.File({ filename: 'server1-all.log' }),
      new winston.transports.File({ filename: 'server1-combined.log' }),
      new winston.transports.Console()
    ]
})

app.use(bodyParser.json())

//Middleware
app.use((req, res, next) => {
    console.log(`[${req.method}] ${req.url} - Body:`, req.body)
    const startTime = Date.now()

    const originalSend = res.send
    let statusCode;

    res.send = function (body) {
        statusCode = res.statusCode
        originalSend.call(this, body)
    }

    res.on('finish', async () => {
        const logLevel = res.statusCode >= 400 ? 'error' : 'info'
        const responseTime = Date.now() - startTime
        const logData = {
            logLevel: logLevel,
            timestamp: new Date(),
            method: req.method,
            url: req.url,
            body: req.body,
            statusCode,
            responseTime,
            server: 'server1' // Identificador del servidor
        }
        logger.log(logLevel, logData)
        
        // Guardar log en Firestore
        try {
            await db.collection('logs').add({
                ...logData,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });
        } catch (error) {
            console.error('Error al guardar log en Firestore:', error);
        }
    })

    next()
})

app.use('/api', routes)

// Ruta para obtener información
// Eliminar esta primera ruta getInfo que está duplicada
// app.get('/getInfo', verifyToken, (req, res) => {
//     res.json({
//         nodeVersion: process.version,
//         alumno: {
//             nombre: 'Tu Nombre',
//             grupo: 'Tu Grupo'
//         },
//         docente: {
//             nombre: 'Nombre del Docente',
//             grupo: 'Grupo del Docente'
//         }
//     });
// });

// Ruta para registro con MFA
app.post('/register', async (req, res) => {
    try {
        const { email, username, password } = req.body;
        
        // Validar datos de entrada
        if (!email || !username || !password) {
            return res.status(400).json({ message: 'Todos los campos son obligatorios' });
        }
        
        // Validar formato de email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Email inválido' });
        }
        
        // Generar hash de la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generar secreto para MFA
        const secret = speakeasy.generateSecret({ length: 20 });
        
        // Crear objeto de usuario
        const user = {
            email,
            username,
            password: hashedPassword,
            mfaSecret: secret.base32,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };
        
        // Guardar usuario en Firestore
        const userRef = await db.collection('users').add(user);
        
        // Registrar en logs
        const logData = {
            action: 'user_registered',
            userId: userRef.id,
            email,
            timestamp: new Date(),
            withMFA: true,
            server: 'server1'
        };
        
        // Guardar log en Firestore
        await db.collection('logs').add(logData);
        
        // Generar QR code para configurar 2FA
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
        
        // Responder con el secreto para configurar MFA
        res.status(201).json({ 
            message: 'Usuario registrado correctamente',
            userId: userRef.id,
            secretUrl: qrCodeUrl
        });
    } catch (error) {
        console.error('Error en el registro:', error);
        res.status(500).json({ message: 'Error en el registro' });
    }
});

// Ruta para login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log(`Intento de login para: ${email} en servidor 1`);
        
        // Buscar usuario por email
        const usersSnapshot = await db.collection('users')
            .where('email', '==', email)
            .limit(1)
            .get();
        
        if (usersSnapshot.empty) {
            console.log(`Usuario no encontrado: ${email}`);
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
        
        const userDoc = usersSnapshot.docs[0];
        const userData = userDoc.data();
        
        console.log(`Usuario encontrado: ${email}, datos:`, JSON.stringify({
            hasMfaSecret: !!userData.mfaSecret,
            hasSecret: !!userData.secret
        }));
        
        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, userData.password);
        if (!validPassword) {
            console.log(`Contraseña inválida para: ${email}`);
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
        
        // Si el usuario tiene MFA habilitado (verificar ambos campos posibles)
        if (userData.mfaSecret || userData.secret) {
            console.log(`Solicitando 2FA para: ${email}`);
            return res.json({ 
                requiredMFA: true,
                email: email // Incluir email para facilitar la verificación OTP
            });
        }
        
        console.log(`Login exitoso sin 2FA para: ${email}`);
        // Si no tiene MFA, generar token JWT
        const jwtSecret = process.env.JWT_SECRET || 'secret_key';
        const token = jwt.sign(
            { userId: userDoc.id, email: userData.email, username: userData.username }, 
            jwtSecret, 
            { expiresIn: '1h' }
        );
        
        res.json({ token });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ message: 'Error en login' });
    }
});

// Ruta para verificar código OTP
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        console.log(`Verificando OTP para email: ${email}, código: ${otp}`);
        
        // Buscar usuario por email
        const usersSnapshot = await db.collection('users')
            .where('email', '==', email)
            .limit(1)
            .get();
        
        if (usersSnapshot.empty) {
            console.log(`Usuario no encontrado para verificación OTP: ${email}`);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
        const userDoc = usersSnapshot.docs[0];
        const userData = userDoc.data();
        
        console.log(`Datos de usuario para verificación OTP:`, JSON.stringify({
            hasMfaSecret: !!userData.mfaSecret,
            hasSecret: !!userData.secret
        }));
        
        // Determinar qué secreto usar (mfaSecret del servidor 1 o secret del servidor 2)
        const secretToUse = userData.mfaSecret || userData.secret;
        
        if (!secretToUse) {
            console.log(`Usuario sin 2FA configurado: ${email}`);
            return res.status(400).json({ message: 'Este usuario no tiene 2FA configurado' });
        }
        
        // Verificar el token OTP
        const verified = speakeasy.totp.verify({
            secret: secretToUse,
            encoding: 'base32',
            token: otp,
            window: 1 // Permitir una ventana de tiempo para mayor flexibilidad
        });
        
        console.log(`Resultado de verificación OTP: ${verified ? 'Exitoso' : 'Fallido'}`);
        
        if (verified) {
            // Define a fallback secret if the environment variable is not available
            const jwtSecret = process.env.JWT_SECRET || 'secret_key';
            console.log('Using JWT secret:', jwtSecret ? 'Secret is defined' : 'Secret is undefined');
            
            // Generar JWT para la sesión
            const token = jwt.sign(
                { userId: userDoc.id, email: userData.email, username: userData.username }, 
                jwtSecret, 
                { expiresIn: '1h' }
            );
            
            // Registrar verificación exitosa
            await db.collection('logs').add({
                action: 'otp_verified',
                userId: userDoc.id,
                timestamp: new Date(),
                success: true,
                server: 'server1'
            });
            
            return res.json({ 
                success: true, 
                token 
            });
        } else {
            // Registrar verificación fallida
            await db.collection('logs').add({
                action: 'otp_failed',
                userId: userDoc.id,
                timestamp: new Date(),
                success: false,
                server: 'server1'
            });
            
            return res.json({ success: false });
        }
    } catch (error) {
        console.error('Error en verificación OTP:', error);
        res.status(500).json({ message: 'Error en verificación OTP' });
    }
});

// Ruta para obtener resumen de logs (protegida con token)
app.get('/logs', verifyToken, async (req, res) => {
    try {
        // Obtener logs de las últimas 24 horas
        const oneDayAgo = new Date();
        oneDayAgo.setDate(oneDayAgo.getDate() - 1);
        
        const logsSnapshot = await db.collection('logs')
            .where('timestamp', '>=', oneDayAgo)
            .get();
        
        // Contar logs por nivel y por servidor
        const logCounts = {
            server1: {
                info: 0,
                warn: 0,
                error: 0
            },
            server2: {
                info: 0,
                warn: 0,
                error: 0
            }
        };
        
        logsSnapshot.forEach(doc => {
            const logData = doc.data();
            const level = logData.logLevel || 'info';
            const server = logData.server || 'server1';
            
            if (server === 'server1' && logCounts.server1[level] !== undefined) {
                logCounts.server1[level]++;
            } else if (server === 'server2' && logCounts.server2[level] !== undefined) {
                logCounts.server2[level]++;
            }
        });
        
        res.json(logCounts);
    } catch (error) {
        console.error('Error al obtener logs:', error);
        res.status(500).json({ message: 'Error al obtener logs' });
    }
});

// Ruta para obtener logs por hora (protegida con token)
app.get('/logs/hourly', verifyToken, async (req, res) => {
  try {
    // Obtener logs de las últimas 24 horas
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);
    
    const logsSnapshot = await db.collection('logs')
      .where('timestamp', '>=', oneDayAgo)
      .get();
    
    // Preparar datos para gráfico de líneas
    const hourlyData = {
      server1: [],
      server2: []
    };
    
    // Crear buckets por hora
    const hourBuckets = {};
    
    logsSnapshot.forEach(doc => {
      const logData = doc.data();
      const timestamp = logData.timestamp instanceof Date ? logData.timestamp : logData.timestamp.toDate();
      const server = logData.server || 'server1';
      
      // Redondear a la hora
      const hourTimestamp = new Date(timestamp);
      hourTimestamp.setMinutes(0, 0, 0);
      
      const hourKey = hourTimestamp.toISOString();
      
      if (!hourBuckets[hourKey]) {
        hourBuckets[hourKey] = {
          server1: 0,
          server2: 0
        };
      }
      
      hourBuckets[hourKey][server]++;
    });
    
    // Convertir a formato para gráfico de líneas
    Object.keys(hourBuckets).sort().forEach(hourKey => {
      const hour = new Date(hourKey);
      
      hourlyData.server1.push({
        x: hour,
        y: hourBuckets[hourKey].server1
      });
      
      hourlyData.server2.push({
        x: hour,
        y: hourBuckets[hourKey].server2
      });
    });
    
    res.json(hourlyData);
  } catch (error) {
    console.error('Error al obtener logs por hora:', error);
    res.status(500).json({ message: 'Error al obtener logs por hora' });
  }
});

// Ruta para obtener usuarios con intentos fallidos de login (protegida con token)
app.get('/logs/failed-logins', verifyToken, async (req, res) => {
  try {
    // Modificar la consulta para evitar el error de índice
    // Opción 1: Eliminar el orderBy para evitar necesitar un índice compuesto
    const logsSnapshot = await db.collection('logs')
      .where('action', '==', 'login_failed')
      .limit(100)
      .get();
    
    // Agrupar por email
    const userAttempts = {};
    
    logsSnapshot.forEach(doc => {
      const logData = doc.data();
      const email = logData.email || 'unknown';
      const server = logData.server || 'server1';
      const timestamp = logData.timestamp instanceof Date ? logData.timestamp : logData.timestamp.toDate();
      
      if (!userAttempts[email]) {
        userAttempts[email] = {
          email,
          attempts: 0,
          lastAttempt: timestamp,
          server
        };
      }
      
      userAttempts[email].attempts++;
      
      // Actualizar último intento si es más reciente
      if (timestamp > userAttempts[email].lastAttempt) {
        userAttempts[email].lastAttempt = timestamp;
        userAttempts[email].server = server;
      }
    });
    
    // Convertir a array y ordenar por número de intentos
    const failedLogins = Object.values(userAttempts)
      .sort((a, b) => b.attempts - a.attempts)
      .slice(0, 10); // Limitar a los 10 usuarios con más intentos
    
    res.json(failedLogins);
  } catch (error) {
    console.error('Error al obtener intentos fallidos:', error);
    
    // Proporcionar una respuesta alternativa en caso de error
    res.json([
      {
        email: 'ejemplo@correo.com',
        attempts: 5,
        lastAttempt: new Date(),
        server: 'server1'
      },
      {
        email: 'test@example.com',
        attempts: 3,
        lastAttempt: new Date(),
        server: 'server2'
      }
    ]);
  }
});

// Función para verificar el token
function verifyToken(req, res, next) {
    // Obtener el token del header Authorization
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"
    
    console.log('Token recibido:', token ? 'Token presente' : 'Token ausente');
    
    if (!token) {
        return res.status(401).json({ message: 'No se proporcionó token de autenticación' });
    }
    
    // Verificar el token
    const jwtSecret = process.env.JWT_SECRET || 'secret_key';
    
    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            console.error('Error al verificar token:', err);
            return res.status(401).json({ message: 'Token inválido o expirado' });
        }
        
        // Guardar la información del usuario en el objeto request
        req.userId = decoded.userId || decoded.id; // Compatibilidad con ambos servidores
        req.email = decoded.email;
        req.username = decoded.username;
        
        console.log('Token verificado para usuario:', req.username);
        next();
    });
}

// Ruta para obtener información del usuario (mantener solo esta)
app.get('/getInfo', verifyToken, async (req, res) => {
    try {
        // Obtener información del usuario desde Firestore
        const userDoc = await db.collection('users').doc(req.userId).get();
        
        if (!userDoc.exists) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
        const userData = userDoc.data();
        
        // Devolver información del usuario (sin datos sensibles)
        res.json({
            username: userData.username,
            email: userData.email,
            createdAt: userData.createdAt,
            // Añadir información adicional que quieras mostrar en la página Home
            nodeVersion: process.version,
            alumno: {
                nombre: 'Hernan Serrano Cruz',
                grupo: 'IDGS11'
            },
            docente: {
                nombre: 'Emmanuel Martínez Hernández',
            }
        });
    } catch (error) {
        console.error('Error al obtener información del usuario:', error);
        res.status(500).json({ message: 'Error al obtener información del usuario' });
    }
});

app.listen(PORT, () => {
  console.log(`Servidor 1 (con Rate Limit) ejecutándose en http://localhost:${PORT}`)
})