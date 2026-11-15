const fs = require("node:fs");
const path = require("node:path");

const runtime = process.env.FIR_TREE_SITTER_RUNTIME;
if (!runtime) {
  console.error("FIR_TREE_SITTER_RUNTIME is required");
  process.exit(2);
}
const { Parser, Language } = require(
  path.join(runtime, "node_modules", "web-tree-sitter", "web-tree-sitter.cjs"),
);
const grammar =
  process.env.FIR_TREE_SITTER_GRAMMAR ||
  path.resolve(runtime, "..", "tree-sitter-python-v0.25.0.proxy.wasm");
const source = path.resolve(process.argv[2]);

(async () => {
  await Parser.init();
  const parser = new Parser();
  parser.setLanguage(await Language.load(grammar));
  const input = fs.readFileSync(source);
  const tree = parser.parse(input.toString("utf8"));
  const errors = [];
  const walk = (node) => {
    if (node.type === "ERROR" || node.isMissing) {
      errors.push({
        type: node.type,
        isMissing: node.isMissing,
        start: node.startPosition,
        end: node.endPosition,
      });
    }
    for (const child of node.children) walk(child);
  };
  walk(tree.rootNode);
  console.log(JSON.stringify({
    rootType: tree.rootNode.type,
    hasError: tree.rootNode.hasError,
    sourceBytes: input.length,
    errorNodeCount: errors.length,
    errors,
  }));
})().catch((error) => {
  console.error(error?.stack || String(error));
  process.exit(1);
});
