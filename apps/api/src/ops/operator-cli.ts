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

/**
 * `node dist/ops/operator-cli.js <command> [--organisation key] [--account id] [--reference ref] [--apply]`
 *
 * Run as a one-off task of the Identity service definition, with its configuration and its
 * secrets, never with values typed on a command line (`docs/runbooks/mfa.md`). Commands:
 *
 *   mfa-reset                    remove a lost factor, end every session      --account --reference
 *   account-disable              disable an account, end every session        --account --reference
 *   sessions-revoke-unsatisfied  end pre-enforcement sessions of covered accounts       --reference
 *   mfa-reencrypt                re-seal TOTP secrets under the primary MFA key
 *
 * Without `--apply`, each reports what it would do and changes nothing.
 */

const USAGE =
  'usage: operator-cli <mfa-reset|account-disable|sessions-revoke-unsatisfied|mfa-reencrypt> ' +
  '--organisation <key> [--account <identifier>] [--reference <ticket>] [--apply]';

export const parseArguments = (
  argv: readonly string[],
): {
  readonly command: string | undefined;
  readonly options: Readonly<Record<string, string | undefined>>;
  readonly apply: boolean;
} => {
  const [command, ...rest] = argv;
  const options: Record<string, string | undefined> = {};
  let apply = false;
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i]!;
    if (flag === '--apply') {
      apply = true;
      continue;
    }
    if (!flag.startsWith('--')) throw new OperatorError(`Unexpected argument. ${USAGE}`);
    options[flag.slice(2)] = rest[i + 1];
    i++;
  }
  return { command, options, apply };
};

export const runCommand = async (deps: OperatorDeps, argv: readonly string[]): Promise<void> => {
  const { command, options, apply } = parseArguments(argv);
  switch (command) {
    case 'mfa-reset':
      await mfaReset(deps, {
        organisation: options.organisation,
        account: options.account,
        reference: options.reference,
        apply,
      });
      return;
    case 'account-disable':
      await accountDisable(deps, {
        organisation: options.organisation,
        account: options.account,
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
      await mfaReencrypt(deps, { organisation: options.organisation, apply });
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
