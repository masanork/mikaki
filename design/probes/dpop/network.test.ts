import { test } from 'node:test';
import { networkScenarios } from './network.ts';
for (const scenario of networkScenarios) test(`${scenario.layer}: ${scenario.id}`, scenario.run);
