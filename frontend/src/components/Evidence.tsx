import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { cx } from "../lib/util";
import { Code, TONE, Tone } from "./ui";

const toneMap: Record<string, Tone> = { ok: "gn", danger: "rd", warn: "am", "": "cy" };

function KV({ items, tone }: { items: string[][]; tone?: string }) {
  return (
    <div className="divide-y divide-line/60 rounded-lg border border-line bg-panel2">
      {items.map(([k, v], i) => (
        <div key={i} className="flex items-start justify-between gap-4 px-3 py-1.5 text-[12px]">
          <span className="text-mute">{k}</span>
          <span className={cx("mono break-all text-right", TONE[toneMap[tone ?? ""] ?? "cy"].text)}>{v}</span>
        </div>
      ))}
    </div>
  );
}

function Side({ s }: { s: any }) {
  const t = toneMap[s.tone ?? ""] ?? "cy";
  return (
    <div className={cx("min-w-0 rounded-lg border p-3", TONE[t].border, TONE[t].bg)}>
      <div className={cx("mb-2 text-[11px] font-bold uppercase tracking-wider", TONE[t].text)}>{s.title}</div>
      {s.code !== undefined && <Code tone={s.tone}>{s.code}</Code>}
      {s.items && <KV items={s.items} tone={s.tone} />}
      {s.text && <div className="text-[12px] text-ink/90">{s.text}</div>}
    </div>
  );
}

const PALETTE = ["#dc2626", "#4f46e5", "#059669", "#d97706", "#7c3aed"];

export function Evidence({ ev }: { ev: any }) {
  return (
    <div className="rise space-y-1.5">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-mute">{ev.title}</div>
      {ev.type === "code" && <Code tone={ev.tone}>{ev.text}</Code>}
      {ev.type === "kv" && <KV items={ev.items} />}
      {ev.type === "table" && (
        <div className="overflow-auto rounded-lg border border-line bg-panel2">
          <table>
            <thead><tr>{ev.columns.map((c: string) => <th key={c}>{c}</th>)}</tr></thead>
            <tbody>{ev.rows.map((r: any[], i: number) => <tr key={i}>{r.map((c, j) => <td key={j} className="mono text-[11.5px]">{String(c)}</td>)}</tr>)}</tbody>
          </table>
        </div>
      )}
      {ev.type === "compare" && <div className="grid gap-2 md:grid-cols-2"><Side s={ev.left} /><Side s={ev.right} /></div>}
      {ev.type === "series" && (
        <div className="h-52 rounded-lg border border-line bg-panel2 p-2">
          <ResponsiveContainer>
            <LineChart data={ev.x.map((x: any, i: number) => Object.fromEntries([["x", x], ...ev.lines.map((l: any) => [l.name, l.values[i]])]))}>
              <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" />
              <XAxis dataKey="x" stroke="#64748b" fontSize={10} />
              <YAxis stroke="#64748b" fontSize={10} unit={ev.unit || ""} />
              <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 8, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {ev.lines.map((l: any, i: number) => <Line key={l.name} type="monotone" dataKey={l.name} stroke={PALETTE[i % 5]} strokeWidth={2} dot={false} />)}
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
