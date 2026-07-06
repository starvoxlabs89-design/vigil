// Convenience shim: `import guardMiddleware from "vigil-guard/express"`
// Same as guard({...}).middleware({...}) but as a single call.
import { guard } from "./index.js";
export default function vigilGuardExpress(opts = {}) {
  const g = guard(opts);
  return g.middleware(opts);
}
