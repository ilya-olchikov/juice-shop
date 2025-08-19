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

test('POST /api/Users', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'csrf',
        'xss',
        'stored_xss',
        'bopla',
        'business_constraint_bypass',
        'html_injection',
        'proto_pollution',
        'nosql'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Users`,
      body: {
        email: 'user1@example.com',
        password: 'strongPassword123!',
        passwordRepeat: 'strongPassword123!',
        username: 'user1'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
