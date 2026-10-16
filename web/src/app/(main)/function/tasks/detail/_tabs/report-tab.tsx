"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, FileTextIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { copyText } from "@/lib/utils";

export function ReportTab({ taskId }: { taskId: string }) {
  const [report, setReport] = React.useState<string>("");
  const [coworkReport, setCoworkReport] = React.useState<string>("");
  const [nativeError, setNativeError] = React.useState<string>("");
  const [coworkError, setCoworkError] = React.useState<string>("");
  const [loading, setLoading] = React.useState(true);
  const [copied, setCopied] = React.useState(false);
  const [refreshKey, setRefreshKey] = React.useState(0);

  React.useEffect(() => {
    let active = true;
    setLoading(true);
    setNativeError("");
    setCoworkError("");
    Promise.allSettled([
      api.report(taskId),
      api.workspaceRead(`tasks/${taskId}/reports/cowork-report.md`),
    ]).then(([nativeResult, coworkResult]) => {
      if (!active) return;
      setReport(nativeResult.status === "fulfilled" ? nativeResult.value : "");
      setNativeError(nativeResult.status === "rejected" ? "ARTEx 기본 보고서를 불러오지 못했습니다." : "");
      setCoworkReport(
        coworkResult.status === "fulfilled" && !coworkResult.value.binary && !coworkResult.value.too_large
          ? coworkResult.value.content ?? ""
          : "",
      );
      // A missing Cowork report is a normal empty state. Other read failures
      // should be visible so a server/API failure is not mistaken for no data.
      setCoworkError(
        coworkResult.status === "rejected"
          ? isMissingWorkspaceFile(coworkResult.reason)
            ? ""
            : "Cowork 보고서 파일을 읽지 못했습니다. 연결과 권한을 확인한 뒤 새로고침해 주세요."
          : coworkResult.value.binary || coworkResult.value.too_large
            ? "Cowork 보고서 파일이 미리보기 가능한 텍스트 파일이 아니거나 크기 제한을 초과했습니다."
            : "",
      );
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [taskId, refreshKey]);

  async function copy() {
    if (!report) return;
    const ok = await copyText(report);
    if (ok) {
      setCopied(true);
      toast.success("已复制 Markdown");
      setTimeout(() => setCopied(false), 1500);
    } else {
      toast.error("复制失败，请手动选择文本复制");
    }
  }

  function isMissingWorkspaceFile(error: unknown): boolean {
    if (!error || typeof error !== "object") return false;
    const status = "status" in error ? Number((error as { status?: unknown }).status) : 0;
    const message = "message" in error ? String((error as { message?: unknown }).message ?? "") : "";
    return status === 404 || /(?:^|\D)404(?:\D|$)/.test(message) || message.includes("文件不存在");
  }

  let content: React.ReactNode;
  if (loading) {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        加载中…
      </div>
    );
  } else if (report) {
    content = (
      <div className="max-h-[60vh] overflow-auto rounded-md border bg-muted/20 p-4">
        <Markdown text={report} />
      </div>
    );
  } else if (nativeError) {
    content = (
      <div role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive">
        {nativeError}
      </div>
    );
  } else {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        暂无报告
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {coworkReport && (
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-sm">
              <FileTextIcon className="size-4" /> Claude Cowork 작성 보고서
            </CardTitle>
            <Button size="sm" variant="outline" onClick={async () => {
              const ok = await copyText(coworkReport);
              if (ok) toast.success("Cowork 보고서 Markdown 복사 완료");
              else toast.error("복사 실패, 텍스트를 직접 선택해 복사해 주세요.");
            }}>
              <CopyIcon /> 복사
            </Button>
          </CardHeader>
          <CardContent>
            <div className="max-h-[60vh] overflow-auto rounded-md border bg-muted/20 p-4">
              <Markdown text={coworkReport} />
            </div>
          </CardContent>
        </Card>
      )}
      {coworkError && (
        <div role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {coworkError}
        </div>
      )}
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-sm">
            <FileTextIcon className="size-4" /> ARTEx 기본 보고서（Markdown）
          </CardTitle>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={() => setRefreshKey((value) => value + 1)} disabled={loading}>
              <RefreshCwIcon className={loading ? "animate-spin" : ""} /> 새로고침
            </Button>
            {report && (
              <Button size="sm" variant="outline" onClick={copy}>
                {copied ? <CheckIcon /> : <CopyIcon />} 复制
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>{content}</CardContent>
      </Card>
    </div>
  );
}
