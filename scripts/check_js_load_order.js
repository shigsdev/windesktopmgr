// check_js_load_order.js -- load-order guard for the split frontend JS (backlog #72).
//
// static/js/app.js + static/js/tabs/*.js are classic <script>s that share
// globals. Inside the old single app.js every function was hoisted, so code
// that ran at load could call a function defined further down. After the
// split, a function in a LATER file does not exist yet while an earlier file
// runs -- that is a ReferenceError on page load.
//
// This walks each file's top-level statements (the code that runs at load,
// following calls into functions synchronously) and fails if any of it uses
// a name declared in a later file. Callbacks (click handlers, DOMContentLoaded,
// timers) are skipped: they run after every script has loaded.
//
// usage: node --expose-internals scripts/check_js_load_order.js <files in load order>
// exit 0 clean / 1 violations / 2 could not run (e.g. acorn missing)
"use strict";
const fs = require("fs");

let acorn;
try {
  acorn = require("internal/deps/acorn/acorn/dist/acorn"); // ships inside Node
} catch (e) {
  console.error("acorn not available: " + e.message);
  process.exit(2);
}

const files = process.argv.slice(2);
const declaredIn = new Map(); // top-level name -> index of the file that declares it
const fnBodies = new Map(); // function name -> names it uses synchronously
const loadTime = []; // [file index, statement]

const isFnNode = n =>
  n && (n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression" || n.type === "FunctionDeclaration");

// Names used by `node`, not descending into nested function bodies unless the
// function is invoked on the spot (an IIFE).
function syncNames(node) {
  const out = new Set();
  (function walk(n, key, parent) {
    if (!n || typeof n.type !== "string") return;
    if (n.type === "Identifier") {
      const isProp = parent && parent.type === "MemberExpression" && key === "property" && !parent.computed;
      const isKey = parent && parent.type === "Property" && key === "key" && !parent.computed;
      if (!isProp && !isKey) out.add(n.name);
      return;
    }
    if (isFnNode(n) && !(parent && parent.type === "CallExpression" && key === "callee")) return;
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) v.forEach(c => walk(c, k, n));
      else if (v && typeof v.type === "string") walk(v, k, n);
    }
  })(node, null, null);
  return out;
}

files.forEach((file, i) => {
  const src = fs.readFileSync(file, "utf8");
  const ast = acorn.parse(src, { ecmaVersion: "latest", sourceType: "script", locations: true });
  for (const s of ast.body) {
    if (s.type === "FunctionDeclaration") {
      declaredIn.set(s.id.name, i);
      fnBodies.set(s.id.name, syncNames(s.body));
      continue;
    }
    if (s.type === "ClassDeclaration") declaredIn.set(s.id.name, i);
    if (s.type === "VariableDeclaration") {
      for (const d of s.declarations) {
        if (d.id.type !== "Identifier") continue;
        declaredIn.set(d.id.name, i);
        if (isFnNode(d.init)) fnBodies.set(d.id.name, syncNames(d.init.body));
      }
    }
    loadTime.push([i, s]);
  }
});

const problems = [];
for (const [i, stmt] of loadTime) {
  const seen = new Set();
  const stack = [...syncNames(stmt)];
  while (stack.length) {
    const name = stack.pop();
    if (seen.has(name)) continue;
    seen.add(name);
    if (declaredIn.has(name) && declaredIn.get(name) > i) {
      problems.push(`${files[i]}:${stmt.loc.start.line}: runs at load but uses ${name} from ${files[declaredIn.get(name)]}`);
    }
    if (fnBodies.has(name)) fnBodies.get(name).forEach(n => stack.push(n));
  }
}

problems.forEach(p => console.error(p));
if (problems.length) {
  console.error(`\n${problems.length} load-order problem(s): move the code or reorder the <script> tags in templates/index.html.`);
  process.exit(1);
}
console.log(`load order OK (${files.length} files)`);
