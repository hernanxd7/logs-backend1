const admin = require('firebase-admin');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');

// Cargar variables de entorno
dotenv.config();

let firebaseConfig;

// Determinar si estamos en desarrollo o producción
const isDevelopment = process.env.NODE_ENV !== 'production';

// En desarrollo, intentar usar el archivo serviceAccountKey.json
if (isDevelopment) {
  try {
    const serviceAccountPath = path.join(__dirname, 'firebase-admin.json');
    if (fs.existsSync(serviceAccountPath)) {
      console.log('Using serviceAccountKey.json for Firebase configuration');
      firebaseConfig = require('./firebase-admin.json');
    } else {
      console.log('serviceAccountKey.json not found, falling back to environment variables');
      useEnvVariables();
    }
  } catch (error) {
    console.error('Error loading serviceAccountKey.json:', error);
    useEnvVariables();
  }
} else {
  // En producción, siempre usar variables de entorno
  useEnvVariables();
}

// Función para configurar Firebase con variables de entorno
function useEnvVariables() {
  console.log('Using environment variables for Firebase configuration');
  firebaseConfig = {
    type: process.env.FIREBASE_TYPE || "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI || "https://accounts.google.com/o/oauth2/auth",
    token_uri: process.env.FIREBASE_TOKEN_URI || "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL || "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN || "googleapis.com"
  };
}

// Inicializar Firebase solo si no está ya inicializado
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(firebaseConfig)
  });
}

const db = admin.firestore();

module.exports = { admin, db };