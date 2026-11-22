"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { remaining, usePoll } from "@/lib/api";
import { Badge, Card, Empty, ErrorState, Loading, StaleNotice, verdictSignal } from "@/components/ui";

interface Row {
  id: string;
  state: string;
  severity: string;
  reason_code: string;
  created_at: string;
  expires_at: string;
  card: { headline?: string };
}

export default function Approvals() {
  const [pending, retryPending] = usePoll<Row[]>("escalations?state=pending", 3000);
  const [recent] = usePoll<Row[]>("escalations?state=recent&limit=25", 10000);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Approvals</h1>
      <Card title="Waiting for a decision">
        {pending.state === "loading" && <Loading />}
        {pending.state === "error" && <ErrorState message={pending.error} retry={retryPending} />}
        {pending.state === "ready" && (
          <>
            {pending.stale && <StaleNotice at={pending.at} />}
            {pending.data.length === 0 ? (
              <Empty>Nothing is waiting. Unanswered requests are denied when their timer runs out.</Empty>
            ) : (
              <ul className="divide-y divide-line">
                {pending.data.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                    <Link href={`/approve/${e.id}`} className="font-medium hover:underline">{e.card?.headline ?? e.id}</Link>
                    <span className="flex items-center gap-3">
                      <span className="tabular text-sm text-muted">{remaining(e.expires_at, now)} left</span>
                      <Badge signal="caution">{e.severity}</Badge>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </Card>
      <Card title="Recently decided">
        {recent.state === "ready" && recent.data.filter((e) => e.state !== "pending").length === 0 && <Empty>No decisions yet.</Empty>}
        {recent.state === "ready" && (
          <ul className="divide-y divide-line">
            {recent.data.filter((e) => e.state !== "pending").map((e) => (
              <li key={e.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <Link href={`/approve/${e.id}`} className="hover:underline">{e.card?.headline ?? e.id}</Link>
                <Badge signal={e.state === "approved" || e.state === "partial" ? "neutral" : verdictSignal(e.state)}>{e.state}</Badge>
              </li>
            ))}
          </ul>
        )}
        {recent.state === "loading" && <Loading />}
      </Card>
    </div>
  );
}
