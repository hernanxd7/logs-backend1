const axios = require('axios');

// Configuración
const API_URL = 'http://localhost:3001/api/register';
const NUM_REQUESTS = 10;
const CONCURRENCY = 5;

// Función para generar datos completamente inválidos (para garantizar errores 400)
function generateInvalidUser(index) {
  // Enviamos objetos vacíos o con datos muy incompletos para forzar error 400
  switch (index % 3) {
    case 0:
      // Objeto vacío - debería fallar siempre
      return {};
    case 1:
      // Solo email, sin username ni password
      return {
        email: `fallido${index}@test.com`
      };
    case 2:
      // Datos con formato incorrecto
      return {
        username: "", // Username vacío
        email: "correo-invalido", // Email sin formato correcto
        password: "" // Password vacío
      };
  }
}

// Función para enviar una petición de registro
async function sendInvalidRegistrationRequest(userData) {
  try {
    console.log(`Intentando registrar datos inválidos: ${JSON.stringify(userData)}`);
    const response = await axios.post(API_URL, userData, {
      headers: { 'Content-Type': 'application/json' }
    });
    console.log(`⚠️ ALERTA: Registro inesperadamente exitoso: ${JSON.stringify(userData)}`);
    return { success: true, expected: false };
  } catch (error) {
    // Verificamos si el error es 400 (Bad Request) como esperamos
    const status = error.response ? error.response.status : 'sin respuesta';
    if (status === 400) {
      console.log(`✅ Error 400 esperado al registrar: ${JSON.stringify(userData)}`);
    } else {
      console.error(`❌ Error con código ${status} (esperábamos 400): ${error.message}`);
    }
    
    return { success: false, expected: status === 400, status };
  }
}

// Función para ejecutar peticiones en paralelo con límite de concurrencia
async function runBulkErrorRegistration() {
  console.log(`Iniciando registro fallido de ${NUM_REQUESTS} usuarios...`);

  let error400Count = 0;
  let otherErrorCount = 0;
  let unexpectedSuccessCount = 0;

  // Divide las peticiones en lotes
  for (let i = 1; i <= NUM_REQUESTS; i += CONCURRENCY) {
    const batch = [];

    for (let j = i; j < i + CONCURRENCY && j <= NUM_REQUESTS; j++) {
      batch.push(sendInvalidRegistrationRequest(generateInvalidUser(j)));
    }

    // Ejecutar las solicitudes en paralelo
    const results = await Promise.all(batch);

    // Contar resultados
    results.forEach(result => {
      if (result.success) {
        unexpectedSuccessCount++;
      } else if (result.expected) {
        error400Count++;
      } else {
        otherErrorCount++;
      }
    });

    console.log(`Progreso: ${Math.min(i + CONCURRENCY - 1, NUM_REQUESTS)}/${NUM_REQUESTS}`);
  }

  console.log('\n===== RESUMEN DE PRUEBA DE ERRORES =====');
  console.log(`✅ Errores 400 (esperados): ${error400Count}`);
  console.log(`❌ Otros errores (no esperados): ${otherErrorCount}`);
  console.log(`⚠️ Registros exitosos (no deberían ocurrir): ${unexpectedSuccessCount}`);
}

// Ejecutar el script
runBulkErrorRegistration().catch(console.error);