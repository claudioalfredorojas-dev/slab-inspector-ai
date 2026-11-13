// Netlify serverless function — PSA certificate lookup.
// Secret PSA_API_TOKEN exists ONLY in Netlify environment variables.
exports.handler = async (event) => {
  const json = (statusCode, body) => ({
    statusCode,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
      'x-content-type-options': 'nosniff' },
    body: JSON.stringify(body)
  });
  if (event.httpMethod !== 'GET') return json(405, { ok:false, error:'Método no permitido.' });
  const cert = String(event.queryStringParameters?.cert || '').trim();
  if (!/^\d{6,12}$/.test(cert)) return json(400, { ok:false, error:'Ingresa un número de certificado PSA válido (6 a 12 dígitos).' });
  const token = process.env.PSA_API_TOKEN;
  if (!token) return json(503, { ok:false, error:'Falta configurar PSA_API_TOKEN en Netlify.' });

  // Optional private preview PIN. Set INSPECTOR_PIN in Netlify for access control.
  const configuredPin = process.env.INSPECTOR_PIN;
  if (configuredPin) {
    const providedPin = String(event.headers?.['x-inspector-pin'] || '');
    const crypto = require('node:crypto');
    const expected = crypto.createHash('sha256').update(configuredPin).digest();
    const actual = crypto.createHash('sha256').update(providedPin).digest();
    if (!crypto.timingSafeEqual(expected,actual)) return json(401,{ok:false,error:'PIN privado incorrecto o no ingresado.'});
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch('https://api.psacard.com/publicapi/cert/GetByCertNumber/' + cert, {
      method: 'GET',
      headers: {'authorization': 'bearer ' + token, 'accept': 'application/json'},
      signal: controller.signal
    });
    if (response.status === 429) return json(429,{ok:false,error:'PSA limitó temporalmente las consultas. Intenta más tarde.'});
    if (!response.ok) return json(502,{ok:false,error:'PSA no pudo completar la consulta (HTTP '+response.status+'). Revisa que el token siga activo y tenga permisos.'});
    let data;
    try { data=await response.json(); } catch {return json(502,{ok:false,error:'PSA devolvió una respuesta que no se pudo interpretar.'})}
    if (data.IsValidRequest === false) return json(400,{ok:false,error:'PSA rechazó el formato del certificado.'});
    if (!data.PSACert) return json(200,{ok:true,found:false,message:'PSA no encontró datos para este certificado.',cert});
    const c=data.PSACert;
    const own=(key,alt) => (c[key] == null ? (alt ? c[alt] : null) : c[key]);
    return json(200,{ok:true,found:true,cert:String(c.CertNumber ?? cert),record: {
      year: own('Year','YearIssued'), brand: c.Brand ?? null, subject:c.Subject ?? null,
      variety:c.Variety ?? null, cardNumber:c.CardNumber ?? null, grade:c.GradeDescription ?? c.CardGrade ?? null,
      category:c.Category ?? null, labelType:c.LabelType ?? null, itemStatus:c.ItemStatus ?? null
    }, message:'Certificado presente en la base consultada; esto NO autentica el slab físico.'});
  } catch(err) {
    return json(502,{ok:false,error:err.name === 'AbortError' ? 'PSA no respondió a tiempo.' : 'Error de conexión al consultar PSA.'});
  } finally {clearTimeout(timeout);}
};
