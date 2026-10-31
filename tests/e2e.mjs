import { chromium } from 'playwright';
import { start, _state } from './mock.mjs';
import fs from 'node:fs';

const server = await start(8090);
const exe = process.env.CHROMIUM_PATH;
const browser = await chromium.launch({ executablePath: exe });
const URL_ = 'http://localhost:8090/?api=/api';
let pass = 0, fail = 0;
const ok = (c, name) => { if (c) { pass++; console.log('  ok  ', name); } else { fail++; console.log('  FAIL', name); } };
const errors = [];

async function person() {
  const ctx = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  const p = await ctx.newPage();
  p.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  p.on('pageerror', (e) => errors.push(String(e)));
  await p.goto(URL_);
  return p;
}
const PW = 'mango river forty two';

try {
  const owner = await person();
  ok(await owner.isVisible('#lockView'), 'lock screen first');
  await owner.fill('#myName', 'Mayank');
  await owner.fill('#pw', 'anything');
  await owner.click('#unlockBtn');
  await owner.waitForFunction(() => /not set up/.test(document.getElementById('lockMsg').textContent));
  ok(true, 'empty repo says not set up');

  await owner.click('#toSetup');
  await owner.fill('#setToken', 'github_pat_WRONG');
  await owner.fill('#setPw', PW); await owner.fill('#setPw2', PW);
  await owner.click('#setupBtn');
  await owner.waitForFunction(() => /did not accept/.test(document.getElementById('setupMsg').textContent));
  ok(true, 'bad key rejected');
  await owner.fill('#setToken', 'github_pat_TESTKEY');
  await owner.fill('#setPw', 'short'); await owner.fill('#setPw2', 'short');
  await owner.click('#setupBtn');
  ok(/12 characters/.test(await owner.textContent('#setupMsg')), 'weak password refused');
  await owner.fill('#setPw', PW); await owner.fill('#setPw2', PW);
  await owner.click('#setupBtn');
  await owner.waitForSelector('#chatView:not([hidden])');
  ok(true, 'owner set up room and is in chat');

  await owner.fill('#text', 'hello friend, see https://example.com/page.');
  await owner.click('#sendBtn');
  await owner.waitForSelector('.item.mine');
  ok((await owner.textContent('.item.mine .bubble')).includes('hello friend'), 'owner sees own message');
  ok(await owner.getAttribute('.item.mine .bubble a', 'href') === 'https://example.com/page', 'link is clickable and trimmed');

  const friend = await person();
  await friend.fill('#myName', 'Ravi');
  await friend.fill('#pw', 'wrong password here');
  await friend.click('#unlockBtn');
  await friend.waitForFunction(() => /Wrong password/.test(document.getElementById('lockMsg').textContent));
  ok(true, 'wrong password refused');
  await friend.fill('#pw', PW);
  await friend.click('#unlockBtn');
  await friend.waitForSelector('.item');
  ok(!(await friend.$('.item.mine')), 'friend sees owner message as not-mine');
  ok((await friend.textContent('.item .meta')).startsWith('Mayank'), 'sender name shown');

  await friend.click('.item .chip');
  const clip = await friend.evaluate(() => navigator.clipboard.readText());
  ok(clip === 'hello friend, see https://example.com/page.', 'copy button copies exact text');

  await friend.fill('#text', 'got it\nsecond line');
  await friend.press('#text', 'Enter');
  await owner.waitForFunction(() => document.querySelectorAll('.item').length === 2, null, { timeout: 8000 });
  ok(true, 'owner receives friend reply via polling');
  ok((await owner.textContent('.item:not(.mine) .bubble')) === 'got it\nsecond line', 'multi-line kept');

  // file send: a tiny PNG
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
  await friend.setInputFiles('#fileIn', { name: 'dot.png', mimeType: 'image/png', buffer: png });
  await owner.waitForSelector('.file img', { timeout: 10000 });
  ok(true, 'image arrives with preview');
  const [dl] = await Promise.all([owner.waitForEvent('download'), owner.click('.item:last-child .chip')]);
  const saved = fs.readFileSync(await dl.path());
  ok(dl.suggestedFilename() === 'dot.png' && saved.equals(png), 'download is byte-identical');

  // data at rest is encrypted
  const all = [..._state.blobs.values()].map((b) => Buffer.from(b, 'base64').toString('latin1')).join('|');
  ok(!all.includes('hello friend') && !all.includes('Ravi') && !all.includes('TESTKEY') && !all.includes('IHDR'), 'nothing readable stored on GitHub');

  // too big file refused
  await owner.evaluate(() => { const dt = new DataTransfer(); });
  // clear room
  owner.once('dialog', (d) => d.accept());
  await owner.click('#clearBtn');
  await owner.waitForFunction(() => document.querySelectorAll('.item').length === 0, null, { timeout: 8000 });
  await friend.waitForFunction(() => document.querySelectorAll('.item').length === 0, null, { timeout: 8000 });
  ok(true, 'clear room empties both screens');
  ok([..._state.curTree().keys()].join() === 'room.json', 'only room.json left after clear');

  // password change locks friend out
  await owner.click('#lockBtn');
  await owner.click('#toSetup');
  await owner.fill('#setToken', 'github_pat_TESTKEY');
  await owner.fill('#setPw', 'new password for today'); await owner.fill('#setPw2', 'new password for today');
  await owner.click('#setupBtn');
  await owner.waitForSelector('#chatView:not([hidden])');
  await friend.waitForSelector('#lockView:not([hidden])', { timeout: 8000 });
  ok(/password was changed/.test(await friend.textContent('#lockMsg')), 'friend locked out after password change');
  await friend.fill('#pw', PW); await friend.click('#unlockBtn');
  await friend.waitForFunction(() => /Wrong password/.test(document.getElementById('lockMsg').textContent));
  ok(true, 'old password no longer works');

  // mobile layout smoke test
  const mctx = await browser.newContext({ viewport: { width: 375, height: 700 }, isMobile: true, hasTouch: true });
  const m = await mctx.newPage(); await m.goto(URL_);
  await m.fill('#pw', 'new password for today'); await m.click('#unlockBtn');
  await m.waitForSelector('#chatView:not([hidden])');
  const overflow = await m.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  ok(!overflow, 'no sideways scroll on phone');
  await m.fill('#text', 'from phone'); await m.click('#sendBtn');
  await m.waitForSelector('.item.mine');
  await m.screenshot({ path: 'tests/phone.png' });
  await owner.waitForFunction(() => document.querySelectorAll('.item').length === 1, null, { timeout: 8000 });
  await owner.fill('#text', 'reply from laptop with a longer sentence so we see wrapping in the bubble'); await owner.click('#sendBtn');
  await m.waitForFunction(() => document.querySelectorAll('.item').length === 2, null, { timeout: 8000 });
  await m.screenshot({ path: 'tests/phone.png' });
  await owner.setViewportSize({ width: 1100, height: 650 });
  await owner.screenshot({ path: 'tests/laptop.png' });
  await friend.screenshot({ path: 'tests/lock.png' });

  ok(errors.filter((e) => !/Failed to load resource/.test(e)).length === 0, 'no console errors / CSP violations' + (errors.length ? ': ' + errors.join(' | ') : ''));
} catch (e) {
  fail++; console.log('  FAIL (exception)', e.message);
} finally {
  console.log(`\n${pass} passed, ${fail} failed`);
  await browser.close(); server.close();
  process.exit(fail ? 1 : 0);
}
