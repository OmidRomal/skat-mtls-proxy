# SKAT mTLS Proxy

Proxy til at håndtere mTLS (mutual TLS) forbindelse til SKAT Sterling File Gateway for eIndkomst.

## Environment Variables

| Variabel | Beskrivelse |
|----------|-------------|
| `OCES3_CERTIFICATE_BASE64` | Dit OCES3 certifikat (PFX/P12) encoded som base64 |
| `OCES3_CERTIFICATE_PASSWORD` | Password til certifikatet |
| `PROXY_API_KEY` | API nøgle til at sikre proxy'en (valgfri men anbefalet) |
| `PORT` | Port (default: 3000) |

## Sådan konverterer du certifikat til base64

```bash
# På Mac/Linux
base64 -i Fikto_Regnskabsprogram.p12 | tr -d '\n' > cert-base64.txt

# På Windows (PowerShell)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("dit-certifikat.p12")) | Out-File cert-base64.txt
```

## Deploy til Railway

1. Push denne mappe til et GitHub repository
2. Opret nyt projekt i Railway og link til repo
3. Tilføj environment variables i Railway dashboard
4. Deploy!

## Endpoints

- `GET /health` - Health check
- `POST /proxy?path=/B2B/...` - Proxy til SKAT

## Brug fra Supabase Edge Function

```typescript
const response = await fetch('https://din-railway-url.railway.app/proxy', {
  method: 'POST',
  headers: {
    'Content-Type': 'text/xml',
    'X-API-Key': 'din-api-key',
    'SOAPAction': 'eIncomeExtractAttached'
  },
  body: soapEnvelope
});
```
