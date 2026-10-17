/** Split the local fixture SQL format: semicolon-separated statements and full-line comments. */
export const sqlParts = (sql: string): string[] =>
  sql
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('--'))
    .join('\n')
    .split(';')
    .map((statement) => statement.trim())
    .filter(Boolean);
