// An operator can reconcile a paused submission to an existing call id.
// A separate credential keeps this write capability out of stats readers' hands.
import { validCallId } from "./outlayer.mjs";

export async function recoverReview(request, env) {
  if (!env.RECOVERY_SECRET || request.headers.get("x-recovery-key") !== env.RECOVERY_SECRET) {
    return new Response("unauthorized", { status: 401 });
  }
  let input;
  try { input = await request.json(); } catch { return new Response("bad body", { status: 400 }); }
  if (![input?.installation, input?.repo_id, input?.pr].every(id => Number.isSafeInteger(id) && id > 0)
    || (input.call_id !== undefined && !validCallId(input.call_id))) {
    return new Response("bad recovery request", { status: 400 });
  }
  const reviews = env.REVIEWS.get(env.REVIEWS.idFromName(`${input.installation}/${input.repo_id}/${input.pr}`));
  try {
    const result = await reviews.recover(input.call_id);
    return Response.json(result, { status: result.recovered ? 200 : 409 });
  } catch {
    return Response.json({ recovered: false, reason: "outlayer_unavailable" }, { status: 503 });
  }
}
