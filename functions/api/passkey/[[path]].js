import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const RP_ID = 'mm-control.pages.dev';
const ORIGIN = `https://${RP_ID}`;
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});
const bytesToBase64 = bytes => btoa(String.fromCharCode(...bytes));
const base64ToBytes = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
async function issueSession(env) {
  const token = crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '');
  await env.PASSKEYS.put(`session:${token}`, 'passkey-owner', { expirationTtl: 604800 });
  return token;
}

export async function onRequest(context) {
  const action = Array.isArray(context.params.path) ? context.params.path.join('/') : context.params.path;
  try {
    if (action === 'status') {
      return json({ available: Boolean(await context.env.PASSKEYS.get('credential')) });
    }
    if (action === 'register-options') {
      if (await context.env.PASSKEYS.get('credential')) return json({ error: 'Passkey already registered' }, 409);
      const body = await context.request.json();
      const options = await generateRegistrationOptions({
        rpName: 'MM Control', rpID: RP_ID, userName: body.username || 'MM Control Owner',
        attestationType: 'none', supportedAlgorithmIDs: [-7, -257],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required', authenticatorAttachment: 'platform' },
      });
      await context.env.PASSKEYS.put('registration-challenge', options.challenge, { expirationTtl: 300 });
      return json(options);
    }
    if (action === 'register-verify') {
      const challenge = await context.env.PASSKEYS.get('registration-challenge');
      if (!challenge) return json({ error: 'Registration expired' }, 400);
      const response = await context.request.json();
      const verification = await verifyRegistrationResponse({ response, expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID });
      if (!verification.verified || !verification.registrationInfo) return json({ verified: false }, 400);
      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
      await context.env.PASSKEYS.put('credential', JSON.stringify({ id: credential.id, publicKey: bytesToBase64(credential.publicKey), counter: credential.counter, transports: credential.transports, deviceType: credentialDeviceType, backedUp: credentialBackedUp }));
      await context.env.PASSKEYS.delete('registration-challenge');
      return json({ verified: true, token: await issueSession(context.env) });
    }
    if (action === 'auth-options') {
      const stored = await context.env.PASSKEYS.get('credential', 'json');
      if (!stored) return json({ error: 'Passkey not registered' }, 404);
      const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'required', allowCredentials: [{ id: stored.id, transports: stored.transports }] });
      await context.env.PASSKEYS.put('authentication-challenge', options.challenge, { expirationTtl: 300 });
      return json(options);
    }
    if (action === 'auth-verify') {
      const stored = await context.env.PASSKEYS.get('credential', 'json');
      const challenge = await context.env.PASSKEYS.get('authentication-challenge');
      if (!stored || !challenge) return json({ error: 'Authentication expired' }, 400);
      const response = await context.request.json();
      const verification = await verifyAuthenticationResponse({ response, expectedChallenge: challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID, credential: { id: stored.id, publicKey: base64ToBytes(stored.publicKey), counter: stored.counter, transports: stored.transports }, requireUserVerification: true });
      if (!verification.verified) return json({ verified: false }, 401);
      stored.counter = verification.authenticationInfo.newCounter;
      await context.env.PASSKEYS.put('credential', JSON.stringify(stored));
      await context.env.PASSKEYS.delete('authentication-challenge');
      return json({ verified: true, token: await issueSession(context.env) });
    }
    return json({ error: 'Not found' }, 404);
  } catch (error) {
    return json({ error: error?.message || 'Passkey error' }, 400);
  }
}
