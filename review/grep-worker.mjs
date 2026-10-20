// Runs one grep of the head commit for review/repo.mjs, in a process it can
// kill: node grep-worker.mjs <root> <json arguments>. Prints the tool's answer.
import { tools } from "./repo.mjs";

const [root, args] = process.argv.slice(2);
process.stdout.write(tools(root, { guarded: false })("grep", JSON.parse(args)));
