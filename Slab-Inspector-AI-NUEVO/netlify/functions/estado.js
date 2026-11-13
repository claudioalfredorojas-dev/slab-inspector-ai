// Diagnóstico sin exponer secretos.
exports.handler = async (event) => ({
  statusCode: 200,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  body: JSON.stringify({
    app: 'Slab Inspector AI',
    functionWorking: true,
    psaTokenConfigured: Boolean(process.env.PSA_API_TOKEN),
    accessPinConfigured: Boolean(process.env.INSPECTOR_PIN),
    message: 'Esta prueba no consulta PSA ni verifica autenticidad.'
  })
});
