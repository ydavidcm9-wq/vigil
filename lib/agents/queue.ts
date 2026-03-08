import { executeAgentRun, AgentRunJob } from "@/lib/agents/executor";
import { listRecoverableRuns, markRunQueued } from "@/lib/agents/store";

const queue: AgentRunJob[] = [];
const queuedRunIds = new Set<string>();
let processing = false;
let recovered = false;
let recoveryPromise: Promise<void> | null = null;

async function recoverPersistedRuns(): Promise<void> {
  if (recovered) return;
  if (recoveryPromise) {
    await recoveryPromise;
    return;
  }

  recoveryPromise = (async () => {
    try {
      const recoverable = await listRecoverableRuns(250);
      for (const run of recoverable) {
        if (run.status === "running") {
          // After process restarts, in-memory queue state is lost; running jobs are safely re-queued.
          await markRunQueued(run.id);
        }
        if (queuedRunIds.has(run.id)) continue;
        queue.push({
          runId: run.id,
          userId: run.user_id,
          agentId: run.agent_id,
          inputText: run.input_text,
        });
        queuedRunIds.add(run.id);
      }
    } catch (err) {
      console.error("[agents/queue] Recovery failed:", err);
    } finally {
      recovered = true;
      recoveryPromise = null;
    }
  })();

  await recoveryPromise;
}

async function processQueue(): Promise<void> {
  if (processing) return;
  processing = true;

  try {
    await recoverPersistedRuns();
    while (queue.length > 0) {
      const next = queue.shift();
      if (!next) continue;
      queuedRunIds.delete(next.runId);
      try {
        await executeAgentRun(next);
      } catch (err) {
        console.error("[agents/queue] Job execution crashed:", err);
      }
    }
  } finally {
    processing = false;
  }
}

export function enqueueAgentRun(job: AgentRunJob): number {
  if (!queuedRunIds.has(job.runId)) {
    queue.push(job);
    queuedRunIds.add(job.runId);
  }

  void recoverPersistedRuns().then(() => processQueue());

  return queue.length + (processing ? 1 : 0);
}

export function forceQueueRecovery(): void {
  void recoverPersistedRuns().then(() => processQueue());
}

export function getQueueState(): { pending: number; processing: boolean } {
  return {
    pending: queue.length,
    processing,
  };
}
