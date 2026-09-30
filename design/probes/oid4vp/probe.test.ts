import test from 'node:test';
import { scenarios } from './cases.ts';

for (const scenario of scenarios) test(`${scenario.layer}: ${scenario.id}`, scenario.run);
