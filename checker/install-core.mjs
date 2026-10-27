import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import path from 'node:path';
const url = 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-compatible-v1.19.33.gz';
// SHA-256 from the maintainer's GitHub release asset digest, checked 2026-10-27.
const sha256 = '386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6';
if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('This pinned artifact requires Linux x64');
const r = await fetch(url, { signal: AbortSignal.timeout(90000) });
if (!r.ok) throw new Error(`Core download failed: HTTP ${r.status}`);
const compressed = Buffer.from(await r.arrayBuffer());
if (crypto.createHash('sha256').update(compressed).digest('hex') !== sha256) throw new Error('Core checksum mismatch');
const destination = path.join(process.env.RUNNER_TEMP || '/tmp', 'subscription-mihomo');
await fs.writeFile(destination, zlib.gunzipSync(compressed), { mode: 0o700 });
await fs.appendFile(process.env.GITHUB_ENV, `MIHOMO_PATH=${destination}\n`);
console.log('Verified and installed Mihomo v1.19.33');
