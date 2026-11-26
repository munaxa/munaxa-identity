import { loadEnvironment } from '@identity/config';

import { PrismaService } from '../persistence/prisma.service.js';
import { buildSecurityStack } from '../platform/security.js';
import {
  OperatorError,
  accountDisable,
  mfaReencrypt,
  mfaReset,
  revokeUnsatisfiedSessions,
  type OperatorDeps,
} from './operator.js';
import {
  ssoAccountConvert,
  ssoAccountCreate,
  ssoConnectionAdd,
  ssoConnectionList,
  ssoConnectionSetEnabled,
} from './sso-operator.js';

/**
 * `node dist/ops/operator-cli.js <command> [--organisation key] [--account id] [--reference ref] [--apply]`
 *
 * Run as a one-off task of the Identity service definition, with its configuration and its
 * secrets, never with values typed on a command line (`docs/runbooks/mfa.md`). Commands:
 *
 *   mfa-reset                    remove a lost factor, end every session      --account-id --reference
 *   account-disable              disable an account, end every session        --account-id --reference
 *   sessions-revoke-unsatisfied  end pre-enforcement sessions of covered accounts       --reference
 *   mfa-reencrypt                re-seal TOTP secrets under the primary MFA key          --reference
 *
 * Company sign-in (`sso-operator.ts`, `docs/runbooks/sso.md`):
 *
 *   sso-connection-add      add a disabled Microsoft or Google connection   --provider --directory --domains
 *   sso-connection-enable   turn a connection on                            --connection-id --reference
 *   sso-connection-disable  turn it off [--end-sessions]                    --connection-id --reference
 *   sso-connection-list     show connections (no changes, no --apply)
 *   sso-account-create      pre-create a company sign-in account [--role]   --connection-id --account
 *   sso-account-convert     move a password account to company sign-in      --connection-id --account-id
 *
 * `--account-id` is preferred to `--account`: an identifier is an email address, and a task
 * override is recorded in CloudTrail.
 *
 * Without `--apply`, each reports what it would do and changes nothing.
 */

const USAGE =
  'usage: operator-cli <mfa-reset|account-disable|sessions-revoke-unsatisfied|mfa-reencrypt|' +
  'sso-connection-add|sso-connection-enable|sso-connection-disable|sso-connection-list|' +
  'sso-account-create|sso-account-convert> ' +
  '--organisation <key> [--account-id <id> | --account <identifier>] [--reference <ticket>] [--apply]';

/** Flags that take no value. Everything else is `--name value`. */
const SWITCHES: ReadonlySet<string> = new Set([
  '--apply',
  '--trust-provider-mfa',
  '--end-sessions',
]);

export const parseArguments = (
  argv: readonly string[],
): {
  readonly command: string | undefined;
  readonly options: Readonly<Record<string, string | undefined>>;
  readonly apply: boolean;
  readonly switches: ReadonlySet<string>;
} => {
  const [command, ...rest] = argv;
  const options: Record<string, string | undefined> = {};
  const switches = new Set<string>();
  let apply = false;
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i]!;
    if (SWITCHES.has(flag)) {
      if (flag === '--apply') apply = true;
      switches.add(flag.slice(2));
      continue;
    }
    if (!flag.startsWith('--')) throw new OperatorError(`Unexpected argument. ${USAGE}`);
    options[flag.slice(2)] = rest[i + 1];
    i++;
  }
  return { command, options, apply, switches };
};

export const runCommand = async (deps: OperatorDeps, argv: readonly string[]): Promise<void> => {
  const { command, options, apply, switches } = parseArguments(argv);
  switch (command) {
    case 'mfa-reset':
      await mfaReset(deps, {
        organisation: options.organisation,
        account: options.account,
        accountId: options['account-id'],
        reference: options.reference,
        apply,
      });
      return;
    case 'account-disable':
      await accountDisable(deps, {
        organisation: options.organisation,
        account: options.account,
        accountId: options['account-id'],
        reference: options.reference,
        apply,
      });
      return;
    case 'sessions-revoke-unsatisfied':
      await revokeUnsatisfiedSessions(deps, {
        organisation: options.organisation,
        reference: options.reference,
        apply,
      });
      return;
    case 'mfa-reencrypt':
      await mfaReencrypt(deps, {
        organisation: options.organisation,
        reference: options.reference,
        apply,
      });
      return;
    case 'sso-connection-add':
      await ssoConnectionAdd(deps, {
        organisation: options.organisation,
        provider: options.provider,
        directory: options.directory,
        domains: options.domains,
        trustProviderMfa: switches.has('trust-provider-mfa'),
        reference: options.reference,
        apply,
      });
      return;
    case 'sso-connection-enable':
    case 'sso-connection-disable':
      await ssoConnectionSetEnabled(deps, {
        organisation: options.organisation,
        connectionId: options['connection-id'],
        enabled: command === 'sso-connection-enable',
        endSessions: switches.has('end-sessions'),
        reference: options.reference,
        apply,
      });
      return;
    case 'sso-connection-list':
      await ssoConnectionList(deps, { organisation: options.organisation });
      return;
    case 'sso-account-create':
      await ssoAccountCreate(deps, {
        organisation: options.organisation,
        connectionId: options['connection-id'],
        account: options.account,
        role: options.role,
        reference: options.reference,
        apply,
      });
      return;
    case 'sso-account-convert':
      await ssoAccountConvert(deps, {
        organisation: options.organisation,
        connectionId: options['connection-id'],
        account: options.account,
        accountId: options['account-id'],
        reference: options.reference,
        apply,
      });
      return;
    default:
      throw new OperatorError(USAGE);
  }
};

const main = async (): Promise<void> => {
  const environment = loadEnvironment();
  const prisma = new PrismaService(environment);
  await prisma.$connect();
  const security = await buildSecurityStack(environment, prisma);
  try {
    await runCommand(
      { security, prisma, out: (line) => process.stdout.write(`${line}\n`) },
      process.argv.slice(2),
    );
  } finally {
    await security.close();
    await prisma.$disconnect();
  }
};

if (require.main === module) {
  main().catch((error: unknown) => {
    // An OperatorError is a refusal written for the operator. Anything else is reported by name
    // only: a driver error can carry a connection string.
    process.stderr.write(
      error instanceof OperatorError
        ? `${error.message}\n`
        : `operator command failed: ${error instanceof Error ? error.name : 'unknown error'}\n`,
    );
    process.exit(1);
  });
}
