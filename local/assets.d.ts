declare module '*.wasm' {
  const binary: ArrayBuffer;
  export default binary;
}

declare module '*.sql' {
  const sql: string;
  export default sql;
}
