import { run, mark, utils } from 'micro-bmark';
import { generateData } from './_shared.js';
import { p256 } from '../p256.js';
import { p384 } from '../p384.js';
import { p521 } from '../p521.js';
import { brainpoolP256r1 } from '../brainpoolP256r1.js';
import { brainpoolP384r1 } from '../brainpoolP384r1.js';
import { brainpoolP512r1 } from '../brainpoolP512r1.js';
import { ed25519 } from '../ed25519.js';
import { ed448 } from '../ed448.js';

run(async () => {
  const RAM = false
  for (let kv of Object.entries({ ed25519, ed448, p256, p384, p521, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 })) {
    const [name, curve] = kv;
    console.log();
    console.log(`\x1b[36m${name}\x1b[0m`);
    if (RAM) utils.logMem();
    await mark('init', 1, () => curve.utils.precompute(8));
    const d = generateData(curve);
    await mark('getPublicKey', 5000, () => curve.getPublicKey(d.priv));
    await mark('sign', 5000, () => curve.sign(d.msg, d.priv));
    await mark('verify', 500, () => curve.verify(d.sig, d.msg, d.pub));
    if (RAM) utils.logMem();
  }
});
