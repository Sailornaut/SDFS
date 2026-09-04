import { EventEmitter } from "node:events";

export type ApprovalEvent = { id: string; status: string; [key: string]: unknown };
const events = new EventEmitter();
events.setMaxListeners(1000);

export function publishApproval(approval: ApprovalEvent) {
  events.emit(approval.id, approval);
}

export function subscribeToApproval(id: string, listener: (approval: ApprovalEvent) => void) {
  events.on(id, listener);
  return () => { events.off(id, listener); };
}
