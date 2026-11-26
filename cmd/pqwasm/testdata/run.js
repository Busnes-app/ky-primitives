// Runs every *.check.js beside this file against pqwasm, under Go's wasm_exec_node.js.
// Usage: node run.js <GOROOT>/lib/wasm/wasm_exec_node.js pqwasm.wasm <repo root>
"use strict";
const fs = require("fs");
const path = require("path");
const [execNode, , root] = process.argv.slice(2);

const checks = fs.readdirSync(__dirname).filter((f) => f.endsWith(".check.js")).sort();
// main.go's js.Global().Set("pqwasm", ...) lands here; run once Go is blocked again.
Object.defineProperty(globalThis, "pqwasm", {
  configurable: true,
  set(pq) {
    Object.defineProperty(globalThis, "pqwasm", { value: pq });
    setImmediate(() => {
      let ran = 0;
      for (const f of checks) {
        ran += require(path.join(__dirname, f))(pq, root);
        console.log("ok", f);
      }
      if (ran === 0) throw new Error("no checks ran");
      console.log(`${ran} checks passed`);
      pq.exit();
    });
  },
});

process.argv.splice(2, 1); // wasm_exec_node.js reads the module path from argv[2]
require(execNode);
