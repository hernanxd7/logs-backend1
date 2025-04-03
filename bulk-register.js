const axios = require('axios');

// Configuración
const API_URL = 'http://localhost:3001/api/register'; // Correcto, usando el prefijo /api
const NUM_REQUESTS = 10;
const CONCURRENCY = 1;

// Función para generar datos aleatorios de usuario
function generateRandomUser(index) {
  return {
    username: `Usuario Test ${index}`, // Cambiado de 'name' a 'username' para coincidir con la API
    email: `usuario${index}@test.com`,
    password: `password${index}`
  };
}

// Función para enviar una petición de registro
async function sendRegistrationRequest(userData) {
  try {
    console.log(`Intentando registrar: ${userData.email} en ${API_URL}`);
    const response = await axios.post(API_URL, userData, {
      headers: { 'Content-Type': 'application/json' }
    });
    console.log(`✅ Usuario registrado: ${userData.email}`);
    return { success: true };
  } catch (error) {
    console.error(`❌ Error al registrar ${userData.email}: ${error.message}`);
    if (error.response) {
      console.error(`  Status: ${error.response.status}`);
      console.error(`  Data: ${JSON.stringify(error.response.data)}`);
    }
    return { success: false };
  }
}

// Función para ejecutar peticiones en paralelo con límite de concurrencia
async function runBulkRegistration() {
  console.log(`Iniciando registro de ${NUM_REQUESTS} usuarios...`);

  let successCount = 0;
  let failCount = 0;

  // Divide las peticiones en lotes de `CONCURRENCY` para evitar sobrecargar el servidor
  const batches = [];
  for (let i = 1; i <= NUM_REQUESTS; i += CONCURRENCY) {
    const batch = [];

    for (let j = i; j < i + CONCURRENCY && j <= NUM_REQUESTS; j++) {
      batch.push(sendRegistrationRequest(generateRandomUser(j)));
    }

    // Ejecutar las solicitudes en paralelo y esperar a que terminen antes de continuar con el siguiente lote
    const results = await Promise.all(batch);

    // Contar éxitos y fracasos
    results.forEach(result => {
      if (result.success) successCount++;
      else failCount++;
    });

    console.log(`Progreso: ${Math.min(i + CONCURRENCY - 1, NUM_REQUESTS)}/${NUM_REQUESTS}`);
  }

  console.log('\n===== RESUMEN =====');
  console.log(`✅ Registros exitosos: ${successCount}`);
  console.log(`❌ Registros fallidos: ${failCount}`);
}

// Ejecutar el script
runBulkRegistration().catch(console.error);
