/** Public scope inventory for the fresh production checkpoint, distinct from isolated packets. */
import { createHash } from 'node:crypto';
import { OWNER_MIGRATIONS } from './production-owner-schema.ts';
import { WORK_MIGRATIONS } from './production-work-schema.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';
import { PRODUCTION_WORK_ADMINISTRATION } from './work-administration-policy.ts';

export const productionWorkPacket = () => ({
  format_version: 1,
  target: PRODUCTION_WORK_TARGET,
  administration: PRODUCTION_WORK_ADMINISTRATION,
  // This existing authority was bootstrapped against the three-file Owner chain.
  // Later additive product migrations cannot change its retained identity.
  owner_migrations: OWNER_MIGRATIONS.slice(0, 3),
  work_migrations: WORK_MIGRATIONS,
});
export const productionWorkPacketDigest = () =>
  createHash('sha256').update(JSON.stringify(productionWorkPacket())).digest('hex');
