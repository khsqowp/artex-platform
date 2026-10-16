"use client";

import * as React from "react";

import { FileText, FlaskConical, Network, RefreshCw } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { api } from "@/lib/api";
import type { CoworkTrafficDetail, CoworkTrafficExchange, TaskNode, WorkspaceEntry } from "@/lib/types";

type ParsedFact = { summary?: string; detail?: string; evidence?: string; confidence?: string };

function factPayload(node: TaskNode): ParsedFact {
  try {
    const value: unknown = JSON.parse(node.payload ?? "{}");
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const row = value as Record<string, unknown>;
      const text = (field: unknown) => (typeof field === "string" ? field : "");
      const confidence = text(row.confidence);
      return {
        summary: text(row.summary) || `事实 #${node.id}`,
        detail: text(row.detail),
        evidence: text(row.evidence),
        confidence: confidence === "observed" || confidence === "inferred" ? confidence : "",
      };
    }
  } catch {
    // Older graph facts may contain plain text payloads.
  }
  return { summary: node.payload ?? "" };
}

function dateLabel(value?: string | number): string {
  if (!value) return "时间未知";
  const timestamp = typeof value === "number" && Math.abs(value) < 1_000_000_000_000 ? value * 1000 : value;
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "时间未知" : date.toLocaleString();
}

function dateTimeValue(value: number): string | undefined {
  const timestamp = Math.abs(value) < 1_000_000_000_000 ? value * 1000 : value;
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function safeTrafficPreview(raw: string): string {
  const redacted = raw
    .replace(/^(authorization|cookie|set-cookie|proxy-authorization):.*$/gim, "$1: [REDACTED]")
    .replace(/((?:password|passwd|token|api[_-]?key|secret)\s*[=:]\s*)[^\s&]+/gi, "$1[REDACTED]");
  const bytes = new TextEncoder().encode(redacted);
  const preview = new TextDecoder().decode(bytes.subarray(0, 8192));
  return bytes.length > 8192 ? `${preview}\n[… truncated …]` : preview;
}

export function RecordsTab({ taskId }: { taskId: string }) {
  const [facts, setFacts] = React.useState<TaskNode[]>([]);
  const [files, setFiles] = React.useState<WorkspaceEntry[]>([]);
  const [traffic, setTraffic] = React.useState<CoworkTrafficExchange[]>([]);
  const [trafficEnabled, setTrafficEnabled] = React.useState(true);
  const [trafficTotal, setTrafficTotal] = React.useState(0);
  const [trafficPage, setTrafficPage] = React.useState(0);
  const [trafficError, setTrafficError] = React.useState("");
  const [expandedCapture, setExpandedCapture] = React.useState("");
  const [captureDetails, setCaptureDetails] = React.useState<Record<string, CoworkTrafficDetail>>({});
  const [captureLoading, setCaptureLoading] = React.useState("");
  const [captureError, setCaptureError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [fileError, setFileError] = React.useState("");
  const [selectedFile, setSelectedFile] = React.useState("");
  const [fileContent, setFileContent] = React.useState("");
  const [fileLoading, setFileLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    setFileError("");
    setTrafficError("");
    const [graphResult, fileResult, trafficResult] = await Promise.allSettled([
      api.explorationGraph(taskId),
      api.workspaceList(`tasks/${taskId}/evidence`),
      api.taskCoworkTraffic(taskId, trafficPage, 50),
    ]);
    if (graphResult.status === "fulfilled") {
      setFacts(
        (graphResult.value.nodes ?? [])
          .filter((node) => node.type === "fact" && node.state !== "origin")
          .slice()
          .reverse(),
      );
    } else {
      setError("任务图谱记录加载失败。");
    }
    if (fileResult.status === "fulfilled") {
      setFiles(
        (fileResult.value.entries ?? [])
          .filter((entry) => !entry.dir)
          .slice()
          .sort((a, b) => b.mtime - a.mtime),
      );
    } else {
      const message = (fileResult.reason as Error)?.message ?? "未知错误";
      // A task with no evidence directory is a legitimate empty state; keep
      // authentication, service, and other read failures visible to the user.
      if (message.includes(": 404") || message.includes("路径不存在")) {
        setFiles([]);
      } else {
        setFiles([]);
        setFileError(`工作区证据文件加载失败：${message}`);
      }
    }
    if (trafficResult.status === "fulfilled") {
      setTraffic(trafficResult.value.exchanges ?? []);
      setTrafficTotal(trafficResult.value.total ?? 0);
      setTrafficEnabled(trafficResult.value.enabled);
    } else {
      setTraffic([]);
      setTrafficTotal(0);
      setTrafficEnabled(false);
      setTrafficError(`Cowork 트래픽 기록을 불러오지 못했습니다: ${(trafficResult.reason as Error)?.message ?? "알 수 없는 오류"}`);
    }
    setLoading(false);
  }, [taskId, trafficPage]);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function openFile(file: WorkspaceEntry) {
    setSelectedFile(file.name);
    setFileContent("");
    setFileLoading(true);
    try {
      const result = await api.workspaceRead(file.path);
      setFileContent(result.content ?? (result.binary ? "该文件是二进制文件，无法在此预览。" : "文件内容为空。"));
    } catch (cause) {
      setFileContent(`读取失败：${(cause as Error).message}`);
    } finally {
      setFileLoading(false);
    }
  }

  async function toggleCapture(captureId: string) {
    setCaptureError("");
    if (expandedCapture === captureId) {
      setExpandedCapture("");
      return;
    }
    setExpandedCapture(captureId);
    if (captureDetails[captureId]) return;
    setCaptureLoading(captureId);
    try {
      const detail = await api.taskCoworkTrafficDetail(taskId, captureId);
      setCaptureDetails((current) => ({ ...current, [captureId]: detail }));
    } catch (cause) {
      setCaptureError(`${captureId}: ${(cause as Error).message}`);
    } finally {
      setCaptureLoading("");
    }
  }

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="flex items-center gap-2 text-base">
            <FlaskConical className="size-4" />
            图谱观察记录 <Badge variant="secondary">{facts.length}</Badge>
          </CardTitle>
          <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className="size-4" />
            刷新
          </Button>
        </CardHeader>
        <CardContent>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {loading ? (
            <p className="text-muted-foreground text-sm">加载中…</p>
          ) : error ? null : facts.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              暂无图谱观察记录。Cowork 写入的 fact 会显示在这里和“探索链路”中。
            </p>
          ) : (
            <ScrollArea className="h-[62vh] pr-3">
              <div className="space-y-3">
                {facts.map((node) => {
                  const fact = factPayload(node);
                  return (
                    <article key={node.id} className="rounded-lg border p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="font-medium">{fact.summary ?? `事实 #${node.id}`}</h3>
                        <Badge variant="outline">{node.origin === "cowork" ? "Cowork" : node.origin || "ARTEx"}</Badge>
                        {fact.confidence && (
                          <Badge variant="secondary">{fact.confidence === "observed" ? "观察" : "推断"}</Badge>
                        )}
                      </div>
                      <p className="mt-1 text-muted-foreground text-xs">
                        #{node.id} · {dateLabel(node.ts)}
                      </p>
                      {fact.detail && <p className="mt-3 whitespace-pre-wrap text-sm">{fact.detail}</p>}
                      {fact.evidence && (
                        <details className="mt-2">
                          <summary className="cursor-pointer text-muted-foreground text-sm">查看依据</summary>
                          <pre className="mt-2 whitespace-pre-wrap break-words rounded bg-muted p-2 text-xs">
                            {fact.evidence}
                          </pre>
                        </details>
                      )}
                    </article>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileText className="size-4" />
            工作区证据文件 <Badge variant="secondary">{files.length}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {fileError && (
            <Alert variant="destructive" className="mb-3">
              <AlertDescription>{fileError}</AlertDescription>
            </Alert>
          )}
          {loading ? (
            <p className="text-muted-foreground text-sm">加载中…</p>
          ) : fileError ? null : files.length === 0 ? (
            <p className="text-muted-foreground text-sm">暂无工作区证据文件。</p>
          ) : (
            <ScrollArea className="h-[62vh] pr-3">
              <div className="space-y-2">
                {files.map((file) => (
                  <article key={file.path} className="rounded-lg border p-3">
                    <button
                      type="button"
                      className="text-left font-medium text-primary text-sm underline-offset-4 hover:underline"
                      onClick={() => void openFile(file)}
                    >
                      {file.name}
                    </button>
                    <p className="mt-1 text-muted-foreground text-xs">
                      {dateLabel(file.mtime)} · {file.size.toLocaleString()} B
                    </p>
                    {selectedFile === file.name && (
                      <div className="mt-3 border-t pt-3">
                        {fileLoading ? (
                          <p className="text-muted-foreground text-sm">文件读取中…</p>
                        ) : (
                          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded bg-muted p-3 text-xs">
                            {fileContent}
                          </pre>
                        )}
                      </div>
                    )}
                  </article>
                ))}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      <Card className="xl:col-span-2">
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="flex items-center gap-2 text-base">
            <Network className="size-4" />
            Cowork 트래픽 기록 <Badge variant="secondary">{trafficTotal}</Badge>
          </CardTitle>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">목록은 메타데이터만 표시하며, 상세 본문은 선택 시 조회합니다</span>
            <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
              <RefreshCw className="size-4" /> 새로고침
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {trafficError ? (
            <Alert variant="destructive"><AlertDescription>{trafficError}</AlertDescription></Alert>
          ) : loading ? (
            <p className="text-sm text-muted-foreground">불러오는 중…</p>
          ) : traffic.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {trafficEnabled
                ? "이 Task에 Cowork가 기록한 트래픽이 없습니다. 승인된 실행에서 record_traffic=yes를 선택하면 요청·응답이 ARTEx Traffic과 이 화면에 연결됩니다."
                : "ARTEx Traffic 저장소를 사용할 수 없어 Cowork 요청 기록을 표시하지 못합니다."}
            </p>
          ) : (
            <>
              <ScrollArea className="max-h-[52vh] pr-3">
                <div className="space-y-2">
                  {traffic.map((exchange) => (
                    <article key={exchange.id} className="rounded-lg border p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline">{exchange.method}</Badge>
                        <Badge variant={exchange.status >= 500 ? "destructive" : "secondary"}>{exchange.status}</Badge>
                        <span className="min-w-0 flex-1 break-all font-mono text-xs" title={exchange.url}>{exchange.url}</span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                        <time dateTime={dateTimeValue(exchange.ts)}>{dateLabel(exchange.ts)}</time>
                        <span>{exchange.content_type || "content type 없음"}</span>
                        <span>응답 {exchange.resp_len.toLocaleString()} B</span>
                        <code className="break-all">{exchange.id}</code>
                      </div>
                      <Button className="mt-3" size="sm" variant="outline" onClick={() => void toggleCapture(exchange.id)}>
                        {expandedCapture === exchange.id ? "상세 닫기" : "요청·응답 상세 보기"}
                      </Button>
                      {expandedCapture === exchange.id && (
                        <div className="mt-3 space-y-3 border-t pt-3">
                          <p className="text-xs text-muted-foreground">
                            캡처 원문에는 민감 정보가 있을 수 있습니다. 인증·쿠키 헤더와 흔한 비밀값 패턴을 가려 각 방향 최대 8 KB만 표시합니다. 이 필터가 모든 개인정보를 찾아내지는 않습니다.
                          </p>
                          {captureLoading === exchange.id ? (
                            <p className="text-sm text-muted-foreground">상세 불러오는 중…</p>
                          ) : captureError.startsWith(`${exchange.id}:`) ? (
                            <Alert variant="destructive"><AlertDescription>{captureError}</AlertDescription></Alert>
                          ) : captureDetails[exchange.id] ? (
                            <div className="grid gap-3 xl:grid-cols-2">
                              {(["req", "resp"] as const).map((side) => (
                                <div key={side}>
                                  <h4 className="mb-1 text-xs font-medium">{side === "req" ? "요청" : "응답"}</h4>
                                  <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3 text-xs">
                                    {safeTrafficPreview(captureDetails[exchange.id][side])}
                                    {(side === "req" ? captureDetails[exchange.id].request_truncated : captureDetails[exchange.id].response_truncated) && "\n[서버 미리보기 8 KB 제한으로 잘렸습니다]"}
                                  </pre>
                                </div>
                              ))}
                            </div>
                          ) : null}
                        </div>
                      )}
                    </article>
                  ))}
                </div>
              </ScrollArea>
              <div className="mt-3 flex items-center justify-between border-t pt-3 text-xs text-muted-foreground">
                <span>페이지 {trafficPage + 1} / {Math.max(1, Math.ceil(trafficTotal / 50))}</span>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" disabled={trafficPage === 0 || loading} onClick={() => setTrafficPage((page) => Math.max(0, page - 1))}>이전</Button>
                  <Button size="sm" variant="outline" disabled={(trafficPage + 1) * 50 >= trafficTotal || loading} onClick={() => setTrafficPage((page) => page + 1)}>다음</Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
