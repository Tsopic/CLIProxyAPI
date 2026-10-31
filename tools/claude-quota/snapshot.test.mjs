import { test } from 'node:test';
import assert from 'node:assert/strict';

import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { collectAndPublish, collectSnapshot, normalizeUsage, retryAfterMS, sanitizeUsage, snapshotHealth, readHealth } from './snapshot.mjs';

const window = (utilization, resets_at = '2026-11-03T07:00:00Z') => ({ utilization, resets_at });
const usage = () => ({ five_hour: window(0, null), seven_day: window(0), seven_day_opus: null, seven_day_sonnet: null });
const syntheticFingerprint = 'a'.repeat(64);

test('a failed account query leaves healthy account observations available', async () => {
  const mock = async (url, options) => {
    if (url.endsWith('/auth-files')) return new Response(JSON.stringify({ files: [
      { type: 'claude', id: 'failed', auth_index: 'failed', credential_fingerprint: syntheticFingerprint },
      { type: 'claude', id: 'healthy', auth_index: 'healthy', credential_fingerprint: syntheticFingerprint },
    ] }));
    const account = JSON.parse(options.body).authIndex;
    return new Response(JSON.stringify(account === 'failed' ? { status_code: 401, body: '{}' } : { status_code: 200, body: JSON.stringify(usage()) }));
  };
  const result = await collectSnapshot('http://example', 'synthetic-key', mock);
  assert.deepEqual(Object.keys(result.accounts), ['healthy']);
});

test('current percent-based limits block Fable without confusing breakdown or paid usage', () => {
  const input = {
    ...usage(),
    limits: [{ kind: 'weekly_scoped', percent: 100, resets_at: '2026-11-03T07:00:00Z', scope: { model: { id: null, display_name: 'Fable' } } }],
    seven_day_breakdown: { items: [] },
    extra_usage: { utilization: 100, resets_at: null },
  };
  const result = normalizeUsage(input);
  assert.equal(result.eligible, true);
  assert.deepEqual(result.blocked_model_families, ['fable']);
});

test('eligibility respects shared weekly, five-hour and OAuth limits', () => {
  for (const key of ['five_hour', 'seven_day', 'seven_day_oauth_apps']) {
    const input = usage(); input[key] = window(100);
    assert.equal(normalizeUsage(input).eligible, false, key);
  }
  assert.equal(normalizeUsage(usage()).eligible, true);
});

test('model-specific limits and missing resets are handled safely', () => {
  const input = usage(); input.seven_day_opus = window(100);
  assert.deepEqual(normalizeUsage(input).blocked_model_families, ['opus']);
  input.five_hour = window(20, null);
  assert.throws(() => normalizeUsage(input));
});

test('snapshot maps credential IDs and fails closed on upstream errors', async () => {
  const mock = async url => url.endsWith('/auth-files') ? new Response(JSON.stringify({files: [{type:'claude', id:'account', auth_index:'index', credential_fingerprint:syntheticFingerprint}]})) : new Response(JSON.stringify({status_code:200, body:JSON.stringify(usage())}));
  assert.equal((await collectSnapshot('http://example', 'synthetic-key', mock)).accounts.account.eligible, true);
  const failed = async url => url.endsWith('/auth-files') ? new Response(JSON.stringify({files: [{type:'claude', id:'account', auth_index:'index', credential_fingerprint:syntheticFingerprint}]})) : new Response(JSON.stringify({status_code:429, body:'{}'}));
  const snapshot = await collectSnapshot('http://example', 'synthetic-key', failed);
  assert.deepEqual(Object.keys(snapshot.accounts), []);
  assert.equal(snapshot.retry_state.account.last_status, 429);
});

// All fixtures and mock credentials are synthetic; no live requests are made.
const expanded = JSON.parse(await readFile(new URL('./fixtures/expanded-usage.json', import.meta.url), 'utf8'));
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const fakeFetch = (onList = () => {}, value = usage()) => async url => {
  if (url.endsWith('/auth-files')) {
    await onList();
    return Response.json({ files: [{ type: 'claude', id: 'synthetic-account', auth_index: 'synthetic-index', credential_fingerprint: syntheticFingerprint }] });
  }
  return Response.json({ status_code: 200, body: JSON.stringify(value) });
};

test('expanded model scopes include Fable, ID-only and display-name-only families', () => {
  assert.deepEqual(normalizeUsage(expanded).blocked_model_families, ['fable', 'opus']);
  assert.equal(normalizeUsage(expanded).eligible, true);
  for (const model of [{ id: 'claude-fable-5' }, { display_name: 'Claude Sonnet 4.6' }]) {
    const input = usage();
    input.limits = [{ ...window(0), locked_reason: 'synthetic restriction', scope: { model } }];
    assert.equal(normalizeUsage(input).blocked_model_families.length, 1);
  }
  const input = usage(); input.seven_day_fable = window(100);
  assert.deepEqual(normalizeUsage(input).blocked_model_families, ['fable']);
});

test('expanded shared and unknown active exhaustion cannot imply eligibility', () => {
  for (const scope of [undefined, {}, { type: 'five_hour' }, { type: 'seven_day' }, { type: 'seven_day_oauth_apps' }, { model: { id: 'future-unknown' } }]) {
    const input = usage(); input.limits = [{ ...window(100), scope }];
    assert.equal(normalizeUsage(input).eligible, false);
    input.limits[0] = { ...window(0), locked_reason: 'synthetic restriction', scope };
    assert.equal(normalizeUsage(input).eligible, false);
    input.limits[0] = { ...window(5), scope };
    assert.equal(normalizeUsage(input).eligible, true);
  }
  const input = usage(); input.seven_day_unknown = window(100);
  assert.equal(normalizeUsage(input).eligible, false);
  input.limits = {};
  assert.throws(() => normalizeUsage(input), /invalid limits/);
});

test('freshness starts before the first request rather than at publication', async () => {
  let clock = new Date('2026-10-28T10:00:00Z');
  const snapshot = await collectSnapshot('http://synthetic', 'synthetic-key', fakeFetch(() => {
    clock = new Date('2026-10-28T10:10:00Z');
  }), () => clock);
  assert.equal(snapshot.observed_at, '2026-10-28T10:00:00.000Z');
  assert.equal(snapshot.accounts['synthetic-account'].observed_at, '2026-10-28T10:10:00.000Z');
  assert.equal(clock - new Date(snapshot.observed_at), 600_000);
});

test('collection and publication hold one kernel lock and preserve ordering', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'claude-quota-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'snapshot.json');
  const entered = deferred(); const release = deferred(); const events = [];
  const first = collectAndPublish(path, 'http://synthetic', 'synthetic-key', {
    now: () => new Date('2026-10-28T10:00:00Z'),
    fetcher: fakeFetch(async () => { events.push('first'); entered.resolve(); await release.promise; }),
  });
  await entered.promise;
  // Probe the actual OS lock while the first collection is suspended.
  assert.equal(spawnSync('flock', ['--nonblock', `${path}.lock`, 'true']).status, 1);
  const second = collectAndPublish(path, 'http://synthetic', 'synthetic-key', {
    now: () => new Date('2026-10-28T10:01:00Z'),
    fetcher: fakeFetch(async () => {
      events.push('second');
      assert.equal(JSON.parse(await readFile(path, 'utf8')).observed_at, '2026-10-28T10:00:00.000Z');
    }),
  });
  release.resolve();
  await Promise.all([first, second]);
  assert.deepEqual(events, ['first', 'second']);
  assert.equal(JSON.parse(await readFile(path, 'utf8')).observed_at, '2026-10-28T10:01:00.000Z');
});

test('collection failure preserves the previous snapshot and releases the lock', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'claude-quota-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'snapshot.json');
  await writeFile(path, 'previous snapshot');
  await assert.rejects(collectAndPublish(path, 'http://synthetic', 'synthetic-key', { fetcher: async () => { throw new Error('synthetic failure'); } }));
  assert.equal(await readFile(path, 'utf8'), 'previous snapshot');
  await collectAndPublish(path, 'http://synthetic', 'synthetic-key', { fetcher: fakeFetch() });
  assert.equal(JSON.parse(await readFile(path, 'utf8')).accounts['synthetic-account'].eligible, true);
});

test('process crash releases lock without PID files or stale-lock deletion', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'claude-quota-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'snapshot.json');
  const source = `import { collectAndPublish } from ${JSON.stringify(new URL('./snapshot.mjs', import.meta.url).href)};
    await collectAndPublish(process.argv[1], 'http://synthetic', 'synthetic-key', {
      fetcher: async () => { process.stdout.write('locked'); await new Promise(() => { setInterval(() => {}, 1000); }); }
    });`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source, path], { stdio: ['ignore', 'pipe', 'inherit'] });
  t.after(() => child.kill('SIGKILL'));
  await once(child.stdout, 'data');
  assert.equal(spawnSync('flock', ['--nonblock', `${path}.lock`, 'true']).status, 1);
  const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited;
  await collectAndPublish(path, 'http://synthetic', 'synthetic-key', { fetcher: fakeFetch() });
  assert.equal(JSON.parse(await readFile(path, 'utf8')).accounts['synthetic-account'].eligible, true);
});

const epoch = Date.parse('2026-10-28T10:00:00Z');
const credential = id => ({ type: 'claude', id, auth_index: `${id}-index`, credential_fingerprint: syntheticFingerprint });
const runner = (files, handler, time, previous = {}, random = () => 0) => collectSnapshot('http://synthetic', 'synthetic-key', async (url, options) => {
  if (url.endsWith('/auth-files')) return Response.json({ files });
  const request = JSON.parse(options.body);
  assert.equal(request.header['User-Agent'], 'claude-code/2.1.273');
  return handler(request.authIndex);
}, () => new Date(time), previous, { random });
const successful = () => Response.json({ status_code: 200, body: JSON.stringify(usage()) });
const broken = () => Response.json({ status_code: 503, body: 'synthetic-secret' });

test('Retry-After accepts wrapper header case, arrays, delta seconds and HTTP dates', () => {
  assert.equal(retryAfterMS({ 'rEtRy-AfTeR': ['180'] }, epoch), 180_000);
  assert.equal(retryAfterMS({ 'Retry-After': 'Wed, 28 Oct 2026 10:04:00 GMT' }, epoch), 240_000);
  for (const value of ['invalid', '-10', '1e20', 'Wed, 28 Oct 2026 09:00:00 GMT']) {
    assert.equal(retryAfterMS({ 'retry-after': value }, epoch), 0);
  }
});

test('normal cadence and repeated failures preserve cache age with capped jittered backoff', async () => {
  const files = [credential('a')];
  let snapshot = await runner(files, successful, epoch);
  const original = snapshot.accounts.a;
  snapshot = await runner(files, () => assert.fail('early request'), epoch + 299_999, snapshot);
  assert.deepEqual(snapshot.accounts.a, original);
  let time = epoch + 300_000;
  for (let failures = 1; failures <= 7; failures++) {
    snapshot = await runner(files, broken, time, snapshot, () => 1);
    assert.equal(snapshot.retry_state.a.failures, failures);
    const deadline = Date.parse(snapshot.retry_state.a.next_attempt_at);
    assert.equal(deadline - time, Math.min(900_000, 60_000 * 2 ** (failures - 1) * 1.2));
    assert.deepEqual(snapshot.accounts.a, original);
    const skipped = await runner(files, () => assert.fail('backoff request'), deadline - 1, snapshot);
    assert.deepEqual(skipped.retry_state.a, snapshot.retry_state.a);
    time = deadline;
  }
  snapshot = await runner(files, successful, time, snapshot);
  assert.equal(snapshot.accounts.a.observed_at, new Date(time).toISOString());
  assert.equal(snapshot.retry_state.a, undefined);
});

test('cache merges independently and deleted, disabled or changed credential indices are pruned', async () => {
  const files = ['a', 'b', 'c', 'd'].map(credential);
  let snapshot = await runner(files, successful, epoch);
  const old = snapshot.accounts.b;
  snapshot = await runner(files, id => id === 'b-index' ? broken() : successful(), epoch + 300_000, snapshot);
  assert.deepEqual(snapshot.accounts.b, old);
  assert.equal(snapshot.accounts.a.observed_at, new Date(epoch + 300_000).toISOString());
  snapshot = await runner([credential('a'), { ...credential('b'), auth_index: 'replacement' }, { ...credential('c'), disabled: true }], broken, epoch + 300_001, snapshot);
  assert.deepEqual(Object.keys(snapshot.accounts), ['a']);
  assert.deepEqual(Object.keys(snapshot.retry_state), ['b']);
  assert.equal(snapshot.retry_state.b.auth_index, 'replacement');
  assert.equal(snapshot.retry_state.b.failures, 1);
});

test('replacement at the same path and index invalidates cache and prior backoff', async () => {
  const files = [credential('a')];
  let snapshot = await runner(files, successful, epoch);
  snapshot = await runner(files, broken, epoch + 300_000, snapshot);
  const replaced = [{ ...credential('a'), credential_fingerprint: 'b'.repeat(64) }];
  snapshot = await runner(replaced, broken, epoch + 300_001, snapshot);
  assert.equal(snapshot.accounts.a, undefined);
  assert.equal(snapshot.retry_state.a.failures, 1);
  assert.equal(snapshot.retry_state.a.credential_fingerprint, 'b'.repeat(64));
});

test('native collection uses fingerprint listing and native API call routes', async () => {
  const paths = [];
  const snapshot = await collectSnapshot('http://synthetic/v8/management', 'synthetic-key', async url => {
    paths.push(new URL(url).pathname);
    if (url.endsWith('/quotas/claude/credentials')) return Response.json({ files: [credential('a')] });
    return successful();
  }, () => new Date(epoch));
  assert.equal(snapshot.accounts.a.eligible, true);
  assert.deepEqual(paths, ['/v8/management/quotas/claude/credentials', '/v8/management/requests/api-call']);
});

test('sanitized unknown limits keep a string kind for cache consumers', () => {
  const sanitized = sanitizeUsage({ ...usage(), limits: [{ kind: 'future_limit', percent: 100, resets_at: '2026-11-03T07:00:00Z' }] });
  assert.equal(sanitized.limits[0].kind, 'unknown');
  assert.equal(normalizeUsage(sanitized).eligible, false);
});

test('upstream global 429 stops requests and retains unqueried accounts, respecting Retry-After', async () => {
  const files = ['a', 'b'].map(credential);
  let snapshot = await runner(files, successful, epoch);
  const old = structuredClone(snapshot.accounts);
  const calls = [];
  snapshot = await runner(files, id => {
    calls.push(id);
    return Response.json({ status_code: 429, header: { 'RETRY-AFTER': ['1200'] }, body: 'synthetic-secret' });
  }, epoch + 300_000, snapshot);
  assert.deepEqual(calls, ['a-index']);
  assert.equal(snapshot.global_retry_at, new Date(epoch + 1_500_000).toISOString());
  assert.deepEqual(JSON.parse(JSON.stringify(snapshot.accounts)), old);
  snapshot = await runner(files, () => assert.fail('global backoff request'), epoch + 1_499_999, snapshot);
  assert.equal(snapshot.retry_state.b, undefined);
  snapshot = await runner(files, successful, epoch + 1_500_000, snapshot);
  assert.equal(snapshot.global_retry_at, undefined);
  assert.equal(snapshot.accounts.b.observed_at, new Date(epoch + 1_500_000).toISOString());
});

test('management HTTP status and malformed upstream status cannot leak response secrets', async () => {
  const files = [credential('a')];
  const management = await runner(files, () => new Response('synthetic-secret', { status: 429, headers: { 'Retry-After': '600' } }), epoch);
  assert.equal(management.retry_state.a.management_status, 429);
  assert.equal(management.retry_state.a.last_status, undefined);
  assert.equal(management.global_retry_at, new Date(epoch + 600_000).toISOString());
  const unknown = await runner(files, () => Response.json({ status_code: 'synthetic-secret', body: 'synthetic-secret' }), epoch);
  assert.equal(unknown.retry_state.a.last_status, undefined);
  assert.equal(JSON.stringify(unknown).includes('synthetic-secret'), false);
});

test('usage cache removes arbitrary fields and lock reasons while retaining eligibility', () => {
  const input = { ...expanded, secret: 'synthetic-secret', seven_day_unknown: { ...window(100), secret: 'synthetic-secret' },
    extra_usage: { is_enabled: true, used_credits: 20, token: 'synthetic-secret' } };
  input.five_hour = { ...window(0), locked_reason: 'synthetic-secret' };
  input.limits[0].token = 'synthetic-secret';
  input.limits[0].scope.model.secret = 'synthetic-secret';
  const safe = sanitizeUsage(input);
  assert.equal(JSON.stringify(safe).includes('synthetic-secret'), false);
  assert.equal(safe.seven_day_unknown, undefined);
  const expected = normalizeUsage(input);
  expected.weekly_reset = new Date(expected.weekly_reset).toISOString();
  expected.five_hour_reset = new Date(expected.five_hour_reset).toISOString();
  assert.deepEqual(normalizeUsage(safe), expected);
  assert.deepEqual(safe.extra_usage, { is_enabled: true, used_credits: 20 });
});

test('legacy and malformed previous state cannot fabricate an observation', async () => {
  for (const entry of [normalizeUsage(usage()), { ...normalizeUsage(usage()), observed_at: new Date(epoch).toISOString(), usage: usage() },
    { auth_index: 'a-index', observed_at: 'bad', usage: usage() },
    { auth_index: 'a-index', observed_at: new Date(epoch + 1).toISOString(), usage: usage() }]) {
    const snapshot = await runner([credential('a')], broken, epoch, { accounts: { a: entry }, retry_state: { a: { failures: -1, next_attempt_at: 'bad' } } });
    assert.equal(snapshot.accounts.a, undefined);
    assert.equal(snapshot.retry_state.a.failures, 1);
  }
});

test('publication persists failed retries and serialized runs re-read their schedule', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'claude-quota-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'snapshot.json');
  let calls = 0;
  const options = { now: () => new Date(epoch), random: () => 0, fetcher: async url => {
    if (url.endsWith('/auth-files')) return Response.json({ files: [credential('a')] });
    calls++; return broken();
  } };
  await Promise.all([collectAndPublish(path, 'http://synthetic', 'synthetic-key', options), collectAndPublish(path, 'http://synthetic', 'synthetic-key', options)]);
  assert.equal(calls, 1);
  assert.equal(JSON.parse(await readFile(path, 'utf8')).retry_state.a.failures, 1);
  await writeFile(path, 'x'.repeat(2 * 1024 * 1024 + 1));
  await collectAndPublish(path, 'http://synthetic', 'synthetic-key', options);
  assert.equal(calls, 2);
});


const inactiveFiveHour = JSON.parse(await readFile(new URL('./fixtures/inactive-five-hour.json', import.meta.url), 'utf8'));

test('explicit inactive five-hour fixture normalizes without accepting missing or malformed shared windows', async () => {
  const safe = sanitizeUsage(inactiveFiveHour);
  assert.deepEqual(safe.five_hour, { utilization: 0, resets_at: null });
  assert.equal(normalizeUsage(inactiveFiveHour).eligible, true);
  const snapshot = await runner([credential('a')], () => Response.json({ status_code: 200, body: JSON.stringify(inactiveFiveHour) }), epoch);
  assert.deepEqual(snapshot.accounts.a.usage.five_hour, safe.five_hour);
  assert.equal(snapshot.health.status, 'healthy');
  for (const input of [
    { seven_day: window(0) }, { five_hour: undefined, seven_day: window(0) },
    { five_hour: null }, { five_hour: null, seven_day: null },
    { five_hour: null, seven_day: {} }, { five_hour: null, seven_day: window(20, null) },
    { five_hour: [], seven_day: window(0) },
  ]) assert.throws(() => sanitizeUsage(input));
});

test('failure reasons are sanitized, persisted and cleared independently of quota eligibility', async () => {
  const files = [credential('a')];
  const initial = await runner(files, successful, epoch);
  const cases = [
    ['transport', () => { throw new Error('synthetic-secret'); }],
    ['management_http', () => new Response('synthetic-secret', { status: 503 })],
    ['wrapper_parse', () => new Response('synthetic-secret')],
    ['wrapper_schema', () => Response.json({ status_code: 'synthetic-secret' })],
    ['wrapper_schema', () => Response.json({ status_code: 200, body: {} })],
    ['upstream_http', broken],
    ['usage_parse', () => Response.json({ status_code: 200, body: 'synthetic-secret' })],
    ['usage_schema', () => Response.json({ status_code: 200, body: JSON.stringify({ five_hour: null }) })],
  ];
  for (const [kind, handler] of cases) {
    const failed = await runner(files, handler, epoch + 300_000, initial);
    assert.equal(failed.retry_state.a.last_error, kind);
    assert.equal(failed.retry_state.a.last_attempt_at, new Date(epoch + 300_000).toISOString());
    assert.deepEqual(failed.accounts.a, initial.accounts.a);
    assert.equal(failed.health.status, 'degraded');
    assert.equal(failed.health.errors[kind], 1);
    assert.equal(failed.account_health.a.last_error, kind);
    assert.equal(failed.account_health.a.backoff, true);
    assert.equal(JSON.stringify(failed).includes('synthetic-secret'), false);
    const skipped = await runner(files, () => assert.fail('backoff should skip request'), epoch + 310_000, failed);
    assert.equal(skipped.account_health.a.last_error, kind);
    const recovered = await runner(files, successful, epoch + 360_000, skipped);
    assert.equal(recovered.account_health.a.last_error, undefined);
    assert.equal(recovered.health.status, 'healthy');
  }
  const exhausted = usage(); exhausted.seven_day = window(100);
  const snapshot = await runner(files, () => Response.json({ status_code: 200, body: JSON.stringify(exhausted) }), epoch);
  assert.equal(snapshot.accounts.a.eligible, false);
  assert.equal(snapshot.health.status, 'healthy');
});

test('health warns before expiry, detects stale heartbeat and never refreshes last-good timestamps', async () => {
  const initial = await runner([credential('a')], successful, epoch);
  assert.equal(snapshotHealth(initial, epoch + 599_999).health.status, 'healthy');
  const warning = snapshotHealth(initial, epoch + 600_000);
  assert.equal(warning.health.status, 'degraded');
  assert.equal(warning.health.warning, 1);
  assert.equal(warning.health.collector_freshness, 'warning');
  assert.equal(warning.account_health.a.last_success_at, initial.accounts.a.observed_at);
  const stale = snapshotHealth(initial, epoch + 1_800_000);
  assert.equal(stale.health.status, 'stale');
  assert.equal(stale.health.stale, 1);
  // Even a forged fresh observation cannot hide a collector that stopped publishing.
  const staleHeartbeat = structuredClone(initial);
  staleHeartbeat.accounts.a.observed_at = new Date(epoch + 1_800_000).toISOString();
  assert.equal(snapshotHealth(staleHeartbeat, epoch + 1_800_000).health.status, 'stale');
  const missing = await runner([credential('a')], broken, epoch);
  assert.equal(missing.health.missing, 1);
  assert.equal(missing.health.status, 'stale');
  assert.equal((await runner([], successful, epoch)).health.status, 'degraded');
});

test('global backoff degrades unqueried accounts and hostile saved reasons are discarded', async () => {
  const files = ['a', 'b'].map(credential);
  const initial = await runner(files, successful, epoch);
  const failed = await runner(files, () => Response.json({ status_code: 429, header: { 'retry-after': '1200' }, body: 'synthetic-secret' }), epoch + 300_000, initial);
  assert.equal(failed.health.backoff, 2);
  assert.equal(failed.account_health.b.status, 'degraded');
  assert.equal(failed.account_health.b.next_attempt_at, failed.global_retry_at);
  failed.retry_state.a.last_error = 'synthetic-secret';
  failed.retry_state.a.last_attempt_at = 'synthetic-secret';
  const checked = snapshotHealth(failed, epoch + 300_001);
  assert.equal(checked.account_health.a.last_error, undefined);
  assert.equal(JSON.stringify(checked).includes('synthetic-secret'), false);
});

test('read-only health CLI requires no key or network and prints only aggregate status', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'claude-quota-health-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'quota.json');
  const time = Date.now();
  const snapshot = await runner([credential('private-account-name')], successful, time);
  await writeFile(path, JSON.stringify(snapshot));
  assert.equal((await readHealth(path, time)).status, 'healthy');
  const invoke = () => spawnSync(process.execPath, [new URL('./snapshot.mjs', import.meta.url).pathname, '--health'], {
    encoding: 'utf8', env: { ...process.env, CLAUDE_QUOTA_SNAPSHOT: path, CLIPROXY_MANAGEMENT_KEY_FILE: join(dir, 'absent-secret-key') },
  });
  let result = invoke();
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).total, 1);
  for (const value of ['private-account-name', syntheticFingerprint, 'absent-secret-key']) assert.equal((result.stdout + result.stderr).includes(value), false);
  snapshot.accounts['private-account-name'].observed_at = new Date(time - 600_000).toISOString();
  await writeFile(path, JSON.stringify(snapshot));
  result = invoke();
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).status, 'degraded');
  await writeFile(path, 'synthetic-secret');
  result = invoke();
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).error, 'snapshot_unavailable');
  assert.equal(result.stderr.includes('synthetic-secret'), false);
});

test('collector CLI publishes retry state before returning nonzero for a degraded collection', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'claude-quota-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'quota.json');
  const keyPath = join(dir, 'key');
  const setup = join(dir, 'mock.mjs');
  await writeFile(keyPath, 'synthetic-secret');
  await writeFile(setup, `globalThis.fetch = async url => url.endsWith('/quotas/claude/credentials')
    ? Response.json({ files: [${JSON.stringify(credential('private-account-name'))}] })
    : Response.json({ status_code: 200, body: 'synthetic-secret' });`);
  const result = spawnSync(process.execPath, ['--import', setup, new URL('./snapshot.mjs', import.meta.url).pathname], {
    encoding: 'utf8', env: { ...process.env, CLAUDE_QUOTA_SNAPSHOT: path, CLIPROXY_MANAGEMENT_KEY_FILE: keyPath },
  });
  assert.equal(result.status, 1);
  const saved = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(saved.retry_state['private-account-name'].last_error, 'usage_parse');
  assert.equal(JSON.parse(result.stdout).errors.usage_parse, 1);
  for (const value of ['synthetic-secret', 'private-account-name', syntheticFingerprint]) assert.equal((result.stdout + result.stderr).includes(value), false);
});

test('installer reproducibly replaces maintained copies without changing quota state or keys', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'claude-quota-install-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const invoke = () => spawnSync(process.execPath, [new URL('./install.mjs', import.meta.url).pathname, '--no-enable'], {
    encoding: 'utf8', env: { ...process.env, HOME: dir },
  });
  let result = invoke();
  assert.equal(result.status, 0, result.stderr);
  const script = join(dir, '.local/share/cliproxyapi-quota/snapshot.mjs');
  const quota = join(dir, '.local/share/cliproxyapi-quota/quota.json');
  await writeFile(quota, 'synthetic-state');
  await writeFile(script, 'obsolete collector');
  result = invoke();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(await readFile(script, 'utf8'), await readFile(new URL('./snapshot.mjs', import.meta.url), 'utf8'));
  assert.equal(await readFile(quota, 'utf8'), 'synthetic-state');
  for (const name of ['cliproxy-claude-quota.service', 'cliproxy-claude-quota.timer', 'cliproxy-claude-quota-health.service', 'cliproxy-claude-quota-health.timer']) {
    const unit = await readFile(join(dir, '.config/systemd/user', name), 'utf8');
    assert.equal(unit.includes('@NODE@'), false);
    if (name.endsWith('.service')) assert.equal(unit.includes(process.execPath), true);
    if (name.includes('-health.service')) {
      assert.equal(unit.includes('--health'), true);
      assert.equal(unit.includes('MANAGEMENT_KEY'), false);
    }
  }
});
