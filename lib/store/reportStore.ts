import type { EventName, ScanReport } from "@/lib/types";
import {
  getReportFromSupabase,
  recordEventToSupabase,
  saveReportToSupabase,
  saveWaitlistEntryToSupabase
} from "@/lib/store/supabaseStore";

interface WaitlistEntry {
  emailHash: string;
  reportId?: string;
  createdAt: string;
}

declare global {
  // eslint-disable-next-line no-var
  var __vibecheckReports: Map<string, ScanReport> | undefined;
  // eslint-disable-next-line no-var
  var __vibecheckEvents: Array<{ name: EventName; reportId?: string; createdAt: string }> | undefined;
  // eslint-disable-next-line no-var
  var __vibecheckWaitlist: WaitlistEntry[] | undefined;
}

const reports = globalThis.__vibecheckReports ?? new Map<string, ScanReport>();
const events = globalThis.__vibecheckEvents ?? [];
const waitlist = globalThis.__vibecheckWaitlist ?? [];

globalThis.__vibecheckReports = reports;
globalThis.__vibecheckEvents = events;
globalThis.__vibecheckWaitlist = waitlist;

export async function saveReport(report: ScanReport) {
  if (await saveReportToSupabase(report)) return;
  reports.set(report.id, report);
}

export async function getReport(id: string) {
  return (await getReportFromSupabase(id)) ?? reports.get(id) ?? null;
}

export async function recordEvent(name: EventName, reportId?: string) {
  if (await recordEventToSupabase(name, reportId)) return;
  events.push({ name, reportId, createdAt: new Date().toISOString() });
}

export async function saveWaitlistEntry(entry: WaitlistEntry) {
  if (await saveWaitlistEntryToSupabase(entry)) return;
  waitlist.push(entry);
}

export function getAggregateSnapshot() {
  return {
    reportCount: reports.size,
    eventCount: events.length,
    waitlistCount: waitlist.length
  };
}
