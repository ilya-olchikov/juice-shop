import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('PUT /api/Users/123', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['http_method_fuzzing', 'id_enumeration', 'bopla'],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.BODY],
      starMetadata: {
        user_roles: [
          'customer',
          'deluxe',
          'accounting',
          'admin'
        ]
      }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/Users/123`,
      body: {
        username: 'alice',
        email: 'alice@example.com',
        password: 's3cr3tP@ssw0rd',
        role: 'customer',
        deluxeToken: '',
        lastLoginIp: '192.168.1.10',
        profileImage: '/assets/public/images/uploads/alice.png',
        isActive: true
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
