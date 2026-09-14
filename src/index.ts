#!/usr/bin/env node

import { execFile } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join, sep } from "node:path";
import { promisify } from "node:util";
import { Adversary, Severity, type RuleContext } from "@adversarylabs/sdk";
import { observeDockerRule, registerDockerfileRules } from "./rules.js";
import { runModelDockerfileReview } from "./model-review.js";

interface DockerfileInstruction {
  keyword: string;
  value: string;
  line: number;
  raw: string;
}

interface DockerfileChangeScope {
  status: "added" | "modified" | "repository";
  changedLines: Set<number>;
}

interface DockerfileStage {
  name: string;
  image: string;
  from: DockerfileInstruction;
  instructions: DockerfileInstruction[];
  isFinal: boolean;
}

interface ParsedDockerfile {
  path: string;
  instructions: DockerfileInstruction[];
  stages: DockerfileStage[];
  changeScope: DockerfileChangeScope;
}

interface RepositoryContext {
  files: string[];
  hasLockfile: boolean;
  hasDockerignore: (dockerfilePath: string) => boolean;
  dockerignoreEntries: (dockerfilePath: string) => string[];
  contextFiles: (dockerfilePath: string) => string[];
}

const SECRET_NAME_PATTERN = /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH|CREDENTIAL)(?:_|$)/i;
const execute = promisify(execFile);
const MAX_REPOSITORY_FILES = 600;
const MAX_DISCOVERY_FILES = 5000;
const SKIPPED_DIRECTORIES = new Set([
  ".adversary",
  ".depot",
  ".direnv",
  ".git",
  ".hg",
  ".next",
  ".svn",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
]);

export function createApp(): Adversary {
  registerDockerfileRules();
  const app = new Adversary({ name: "dockerfile", version: "0.0.21" });

  app.rule("dockerfile.review", async (ctx) => {
    const dockerfiles = await loadDockerfiles(ctx);
    const repo = await inspectRepository(ctx);
    const severities: string[] = [];
    const detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = [];

    ctx.summary.files_scanned = dockerfiles.length;

    for (const dockerfile of dockerfiles) {
      reportBaseImageObservations(ctx, dockerfile, repo, severities, detections);
      reportSecretObservations(ctx, dockerfile, severities, detections);
      reportBroadCopyObservations(ctx, dockerfile, repo, severities, detections);
      reportRuntimeObservations(ctx, dockerfile, severities, detections);
      reportRemoteAddObservations(ctx, dockerfile, severities, detections);
      reportCurlBashObservations(ctx, dockerfile, severities, detections);
      reportMutableExternalArtifactObservations(ctx, dockerfile, severities, detections);
      reportMissingBuildArgumentObservations(ctx, dockerfile, severities, detections);
      reportMissingDockerignoreObservations(ctx, dockerfile, repo, severities, detections);
      reportSecretLayerHistoryObservations(ctx, dockerfile, severities, detections);
      reportPositiveSignals(ctx, dockerfile);
      reportReviewObservations(ctx, dockerfile);
    }

    const sources = [];
    for (const df of dockerfiles) {
      try {
        const { readFile } = await import("node:fs/promises");
        const { join } = await import("node:path");
        sources.push({ path: df.path, content: await readFile(join(ctx.repoPath, df.path), "utf8") });
      } catch {
        // ignore
      }
    }
    const modelStatus = await runModelDockerfileReview(
      ctx,
      detections,
      sources,
      severities,
      detections[0]?.message,
    );
    if (modelStatus === "unavailable") {
      reportOpinion(ctx, dockerfiles, severities);
    }
  });

  return app;
}

async function loadDockerfiles(ctx: RuleContext): Promise<ParsedDockerfile[]> {
  const sources = await ctx.loadInScopeSources({
    include: isDockerfilePath,
    ignoreDirectories: [...SKIPPED_DIRECTORIES],
    limit: MAX_DISCOVERY_FILES,
  });

  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  return Promise.all(sources
    .sort((left, right) => left.path.localeCompare(right.path))
    .map(async ({ path, content, status }) => {
      const instructions = parseDockerfile(content);
      return {
        path,
        instructions,
        stages: parseStages(instructions),
        changeScope: wholeTarget || status === "repository"
          ? { status: "repository", changedLines: new Set<number>() }
          : await dockerfileChangeScope(ctx, path),
      };
    }));
}

async function dockerfileChangeScope(ctx: RuleContext, path: string): Promise<DockerfileChangeScope> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { status: "added", changedLines: new Set<number>() };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  try {
    const { stdout } = await execute("git", ["-C", ctx.repoPath, ...args], {
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
    });
    return { status: "modified", changedLines: changedLineNumbers(stdout) };
  } catch {
    return { status: "modified", changedLines: new Set<number>() };
  }
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

function areDirectLinesEligible(dockerfile: ParsedDockerfile, lines: readonly number[]): boolean {
  if (dockerfile.changeScope.status !== "modified") return true;
  return lines.some((line) => dockerfile.changeScope.changedLines.has(line));
}

function instructionLinesMatching(
  instruction: DockerfileInstruction,
  predicate: (line: string) => boolean,
): number[] {
  const lines = instruction.raw.split(/\r?\n/)
    .map((line, index) => ({ line, number: instruction.line + index }))
    .filter(({ line }) => predicate(line))
    .map(({ number }) => number);
  return lines.length > 0 ? lines : [instruction.line];
}

async function inspectRepository(ctx: RuleContext): Promise<RepositoryContext> {
  const files = await walkRepository(ctx.repoPath);
  const fileSet = new Set(files);
  const dockerignoreCache = new Map<string, string[]>();

  for (const path of files.filter((file) => file.endsWith(".dockerignore"))) {
    try {
      dockerignoreCache.set(path, parseDockerignore(await readFile(join(ctx.repoPath, path), "utf8")));
    } catch {
      dockerignoreCache.set(path, []);
    }
  }

  const lockfiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "poetry.lock", "Pipfile.lock", "go.sum"];

  return {
    files,
    hasLockfile: lockfiles.some((path) => fileSet.has(path)),
    hasDockerignore(dockerfilePath: string): boolean {
      return fileSet.has(dockerignorePathFor(dockerfilePath));
    },
    dockerignoreEntries(dockerfilePath: string): string[] {
      return dockerignoreCache.get(dockerignorePathFor(dockerfilePath)) ?? [];
    },
    contextFiles(dockerfilePath: string): string[] {
      const directory = dirname(dockerfilePath);
      const contextRoot = directory === "." ? "" : `${toPosixPath(directory)}/`;
      const entries = dockerignoreCache.get(dockerignorePathFor(dockerfilePath)) ?? [];
      return files.filter((file) => file.startsWith(contextRoot)).filter((file) => !isIgnoredByDockerignore(file.slice(contextRoot.length), entries));
    },
  };
}

function reportBaseImageObservations(ctx: RuleContext, dockerfile: ParsedDockerfile, repo: RepositoryContext, severities: string[], detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = []): void {
  for (const stage of dockerfile.stages) {
    const anchors = instructionLinesMatching(stage.from, (line) => line.includes(stage.image));
    if (!stage.image.includes("$") && !areDirectLinesEligible(dockerfile, anchors)) continue;
    if (isScratch(stage.image) || hasDigest(stage.image)) {
      continue;
    }

    severities.push(Severity.Low);
    detections.push({ ruleId: "dockerfile.base-image.unpinned-digest", file: dockerfile.path, line: stage.from.line, snippet: stage.from.raw, message: "Base image not pinned by digest", severity: Severity.Low });
    observeDockerRule(ctx, {
      ruleId: "dockerfile.base-image.unpinned-digest",
      subject: stage.image,
      severity: Severity.Low,
      confidence: imageTag(stage.image) === undefined || imageTag(stage.image) === "latest" ? "high" : "medium",
      location: { file: dockerfile.path, line: stage.from.line },
      evidence: {
        stage: stage.name,
        instruction: stage.from.raw,
        image: stage.image,
        lockfilePresent: repo.hasLockfile,
      },
    });
  }
}

function reportSecretObservations(ctx: RuleContext, dockerfile: ParsedDockerfile, severities: string[], detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = []): void {
  for (const instruction of dockerfile.instructions) {
    if (instruction.keyword !== "ARG" && instruction.keyword !== "ENV") {
      continue;
    }

    for (const name of variableNames(instruction)) {
      if (!SECRET_NAME_PATTERN.test(name)) {
        continue;
      }
      const anchors = instructionLinesMatching(instruction, (line) => new RegExp(`\\b${escapeRegExp(name)}\\b`).test(line));
      if (!areDirectLinesEligible(dockerfile, anchors)) continue;

      severities.push(Severity.High);
      detections.push({ ruleId: "dockerfile.secret.arg-env", file: dockerfile.path, line: instruction.line, snippet: instruction.raw, message: `Secret-like ${name} in ARG/ENV`, severity: Severity.High });
      observeDockerRule(ctx, {
        ruleId: "dockerfile.secret.arg-env",
        subject: name,
        severity: Severity.High,
        confidence: "medium",
        location: { file: dockerfile.path, line: instruction.line },
        evidence: {
          instruction: instruction.raw,
          variable: name,
        },
      });
    }
  }
}

function reportBroadCopyObservations(ctx: RuleContext, dockerfile: ParsedDockerfile, repo: RepositoryContext, severities: string[], detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = []): void {
  for (const stage of dockerfile.stages) {
    for (const instruction of stage.instructions) {
      if ((instruction.keyword !== "COPY" && instruction.keyword !== "ADD") || !copiesWholeContext(instruction.value)) {
        continue;
      }

      const effectiveContext = repo.contextFiles(dockerfile.path);
      const notableIncludedFiles = effectiveContext.filter((file) => isLikelyUnneededInImage(file) || isLikelySensitiveContextFile(file)).slice(0, 8);
      const dockerignorePresent = repo.hasDockerignore(dockerfile.path);
      const reachesRuntime = stage.isFinal || finalStageCopiesFromStage(dockerfile, stage.name);
      const confidence = notableIncludedFiles.length > 0 || !dockerignorePresent ? "medium" : "low";

      if (confidence === "low" && effectiveContext.length < 40) {
        continue;
      }

      severities.push(Severity.Info);
      detections.push({ ruleId: "dockerfile.copy.broad-context", file: dockerfile.path, line: instruction.line, snippet: instruction.raw, message: "Broad COPY of build context", severity: Severity.Info });
      observeDockerRule(ctx, {
        ruleId: "dockerfile.copy.broad-context",
        subject: dockerfile.path,
        severity: Severity.Info,
        confidence,
        location: { file: dockerfile.path, line: instruction.line },
        evidence: {
          stage: stage.name,
          instruction: instruction.raw,
          effectiveFileCount: effectiveContext.length,
          notableIncludedFiles,
          dockerignorePresent,
          reachesRuntime,
          dockerignoreEntries: repo.dockerignoreEntries(dockerfile.path),
        },
      });
    }
  }
}

function reportRuntimeObservations(ctx: RuleContext, dockerfile: ParsedDockerfile, severities: string[], detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = []): void {
  const stage = dockerfile.stages.find((candidate) => candidate.isFinal);
  if (stage === undefined) {
    return;
  }

  const lastUser = stage.instructions.filter((instruction) => instruction.keyword === "USER").slice(-1)[0];
  if (lastUser !== undefined && !isRootUser(lastUser.value)) {
    return;
  }

  severities.push(Severity.Medium);
  detections.push({ ruleId: "dockerfile.runtime.root-user", file: dockerfile.path, line: lastUser?.line ?? stage.from.line, snippet: lastUser?.raw ?? stage.from.raw, message: "Runtime stage runs as root", severity: Severity.Medium });
  observeDockerRule(ctx, {
    ruleId: "dockerfile.runtime.root-user",
    subject: dockerfile.path,
    severity: Severity.Medium,
    confidence: "high",
    location: { file: dockerfile.path, line: lastUser?.line ?? stage.from.line },
    evidence: {
      stage: stage.name,
      instruction: lastUser?.raw,
      defaultUser: lastUser === undefined ? "root" : lastUser.value,
    },
  });
}

function reportRemoteAddObservations(
  ctx: RuleContext,
  dockerfile: ParsedDockerfile,
  severities: string[],
  detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = [],
): void {
  for (const instruction of dockerfile.instructions) {
    if (instruction.keyword !== "ADD") continue;
    const url = instruction.value.trim().split(/\s+/)[0] ?? "";
    if (!/^https?:\/\//i.test(url)) continue;
    const anchors = instructionLinesMatching(instruction, (line) => line.includes(url));
    if (!areDirectLinesEligible(dockerfile, anchors)) continue;
    severities.push(Severity.High);
    detections.push({
      ruleId: "dockerfile.add.remote-url",
      file: dockerfile.path,
      line: instruction.line,
      snippet: instruction.raw,
      message: "ADD fetches a remote URL",
      severity: Severity.High,
    });
    observeDockerRule(ctx, {
      ruleId: "dockerfile.add.remote-url",
      subject: dockerfile.path,
      severity: Severity.High,
      confidence: "high",
      location: { file: dockerfile.path, line: instruction.line, snippet: instruction.raw },
      evidence: { instruction: instruction.raw },
    });
  }
}

function reportCurlBashObservations(
  ctx: RuleContext,
  dockerfile: ParsedDockerfile,
  severities: string[],
  detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = [],
): void {
  for (const instruction of dockerfile.instructions) {
    if (instruction.keyword !== "RUN") continue;
    if (!/\b(?:curl|wget)\b[^|&;\n]*\|\s*(?:ba)?sh\b/i.test(instruction.value)) continue;
    const anchors = instructionLinesMatching(
      instruction,
      (line) => /\b(?:curl|wget)\b/i.test(line) || /\|\s*(?:ba)?sh\b/i.test(line),
    );
    if (!areDirectLinesEligible(dockerfile, anchors)) continue;
    severities.push(Severity.High);
    detections.push({
      ruleId: "dockerfile.shell.curl-bash",
      file: dockerfile.path,
      line: instruction.line,
      snippet: instruction.raw,
      message: "curl|bash install pattern",
      severity: Severity.High,
    });
    observeDockerRule(ctx, {
      ruleId: "dockerfile.shell.curl-bash",
      subject: dockerfile.path,
      severity: Severity.High,
      confidence: "high",
      location: { file: dockerfile.path, line: instruction.line, snippet: instruction.raw },
      evidence: { instruction: instruction.raw },
    });
  }
}

function reportMutableExternalArtifactObservations(
  ctx: RuleContext,
  dockerfile: ParsedDockerfile,
  severities: string[],
  detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = [],
): void {
  for (const instruction of dockerfile.instructions) {
    if (instruction.keyword !== "RUN" || !/\b(?:curl|wget)\b/i.test(instruction.value)) continue;
    if (/\b(?:curl|wget)\b[^|&;\n]*\|\s*(?:ba)?sh\b/i.test(instruction.value)) continue;
    if (verifiesDownloadedArtifact(instruction.value)) continue;

    for (const url of externalURLs(instruction.value)) {
      const mutability = mutableArtifactReason(url);
      if (mutability === undefined) continue;

      severities.push(Severity.Medium);
      detections.push({
        ruleId: "dockerfile.external-artifact.mutable",
        file: dockerfile.path,
        line: instruction.line,
        snippet: instruction.raw,
        message: "External artifact uses a mutable download URL",
        severity: Severity.Medium,
      });
      observeDockerRule(ctx, {
        ruleId: "dockerfile.external-artifact.mutable",
        subject: dockerfile.path,
        severity: Severity.Medium,
        confidence: mutability === "moving-selector" ? "high" : "medium",
        location: { file: dockerfile.path, line: instruction.line, snippet: instruction.raw },
        evidence: { instruction: instruction.raw, url, mutability },
      });
    }
  }
}

function reportMissingBuildArgumentObservations(
  ctx: RuleContext,
  dockerfile: ParsedDockerfile,
  severities: string[],
  detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = [],
): void {
  const stageByName = new Map(
    dockerfile.stages.map((stage) => [stage.name.toLowerCase(), stage]),
  );

  for (const stage of dockerfile.stages) {
    const available = inheritedBuildVariables(stage, stageByName);
    for (const instruction of stage.instructions) {
      if (instruction.keyword === "FROM") continue;

      if (instruction.keyword === "ARG") {
        for (const name of variableNames(instruction)) available.add(name);
        continue;
      }

      if (instruction.keyword !== "RUN" && instruction.keyword !== "LABEL" &&
          instruction.keyword !== "ENV") {
        continue;
      }

      for (const reference of buildVariableReferences(instruction)) {
        if (!isVersionBuildVariable(reference.name) || available.has(reference.name)) {
          continue;
        }

        severities.push(Severity.Medium);
        detections.push({
          ruleId: "dockerfile.build-arg.missing",
          file: dockerfile.path,
          line: instruction.line,
          snippet: instruction.raw,
          message: `${reference.name} is used before it is declared in ${stage.name}.`,
          severity: Severity.Medium,
        });
        observeDockerRule(ctx, {
          ruleId: "dockerfile.build-arg.missing",
          subject: reference.name,
          severity: Severity.Medium,
          confidence: "high",
          location: { file: dockerfile.path, line: instruction.line },
          evidence: {
            stage: stage.name,
            variable: reference.name,
            instruction: instruction.raw,
          },
        });
      }

      if (instruction.keyword === "ENV") {
        for (const name of variableNames(instruction)) available.add(name);
      }
    }
  }
}

function inheritedBuildVariables(
  stage: DockerfileStage,
  stageByName: Map<string, DockerfileStage>,
  visited = new Set<string>(),
): Set<string> {
  const variables = new Set<string>();
  const parent = stageByName.get(stage.image.toLowerCase());
  if (parent === undefined) {
    return variables;
  }

  const parentKey = parent.name.toLowerCase();
  if (visited.has(parentKey)) {
    return variables;
  }
  visited.add(parentKey);

  for (const name of inheritedBuildVariables(parent, stageByName, visited)) {
    variables.add(name);
  }
  for (const instruction of parent.instructions) {
    if (instruction.keyword === "ARG" || instruction.keyword === "ENV") {
      for (const name of variableNames(instruction)) variables.add(name);
    }
  }
  return variables;
}

function buildVariableReferences(instruction: DockerfileInstruction): Array<{ name: string }> {
  if (instruction.keyword === "RUN" && instruction.value.trimStart().startsWith("[")) {
    return [];
  }

  const value = instruction.keyword === "RUN"
    ? instruction.value.slice(0, shellCommentStart(instruction.value))
    : instruction.value;
  const references: Array<{ name: string }> = [];
  const seen = new Set<string>();
  const pattern = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(value)) !== null) {
    if (isEscapedAt(value, match.index)) continue;
    if (instruction.keyword === "RUN" && isInsideSingleQuotes(value, match.index)) continue;

    const parameterOperation = match[2] ?? "";
    if (/^:?[-+?=]/.test(parameterOperation)) continue;

    const name = match[1] ?? match[3];
    if (name !== undefined && !seen.has(name)) {
      seen.add(name);
      references.push({ name });
    }
  }
  return references;
}

function shellCommentStart(value: string): number {
  let quote: "single" | "double" | undefined;

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\\" && quote !== "single") {
      index += 1;
      continue;
    }
    if (character === "'" && quote !== "double") {
      quote = quote === "single" ? undefined : "single";
      continue;
    }
    if (character === '"' && quote !== "single") {
      quote = quote === "double" ? undefined : "double";
      continue;
    }
    if (character === "#" && quote === undefined &&
        (index === 0 || /[\s;&|()<>]/.test(value[index - 1] ?? ""))) {
      return index;
    }
  }

  return value.length;
}

function isEscapedAt(value: string, offset: number): boolean {
  let backslashes = 0;
  for (let index = offset - 1; index >= 0 && value[index] === "\\"; index -= 1) {
    backslashes += 1;
  }
  return backslashes % 2 === 1;
}

function isInsideSingleQuotes(value: string, offset: number): boolean {
  let inside = false;
  for (let index = 0; index < offset; index += 1) {
    if (value[index] === "'") inside = !inside;
  }
  return inside;
}

function isVersionBuildVariable(name: string): boolean {
  return /^(?:VERSION|BUILD_VERSION|APP_VERSION|APPLICATION_VERSION|RELEASE_VERSION|IMAGE_VERSION|PACKAGE_VERSION|COMPONENT_VERSION|ARTIFACT_VERSION)$/.test(name);
}

function externalURLs(value: string): string[] {
  return [...value.matchAll(/https?:\/\/[^\s"'\\|;&)]+/gi)].map((match) => match[0].replace(/[.,]+$/, ""));
}

function mutableArtifactReason(url: string): "moving-selector" | "unversioned-artifact" | undefined {
  const lower = url.toLowerCase();
  if (/(?:^|[/?#._-])(?:latest|main|master)(?:$|[/?#._-])/.test(lower)) {
    return "moving-selector";
  }
  if (hasStableArtifactSelector(url)) {
    return undefined;
  }
  if (/(?:\.tar(?:\.(?:gz|bz2|xz|zst))?|\.zip|\.jar|\.war|\.whl|\.deb|\.rpm|\.apk|\.tgz|\.txz|\.gz|\.xz|\.bz2|\.exe|\.msi|\.bin|\.sh)(?:[?#]|$)/i.test(url)) {
    return "unversioned-artifact";
  }
  return undefined;
}

function hasStableArtifactSelector(url: string): boolean {
  return (
    /(?:^|[/?#._-])v?\d+(?:\.\d+)+(?:[-+][a-z0-9.-]+)?(?:$|[/?#._-])/i.test(url) ||
    /(?:^|[/?#._-])[a-f0-9]{12,40}(?:$|[/?#._-])/i.test(url) ||
    /\$\{?[a-z0-9_]*version\}?/i.test(url)
  );
}

function verifiesDownloadedArtifact(value: string): boolean {
  return (
    /\bsha(?:256|384|512)sum\b[^;&\n]*(?:\s-c\b|\s--check\b)/i.test(value) ||
    /\bshasum\b[^;&\n]*\s-a\s+(?:256|384|512)\b[^;&\n]*(?:\s-c\b|\s--check\b)/i.test(value) ||
    /\bopenssl\s+dgst\b[^;&\n]*(?:-verify|-prverify)\b/i.test(value) ||
    /\bgpg2?\s+--verify\b/i.test(value) ||
    /\bcosign\s+verify\b/i.test(value) ||
    /\bminisign\s+-V\b/i.test(value)
  );
}

function reportMissingDockerignoreObservations(
  ctx: RuleContext,
  dockerfile: ParsedDockerfile,
  repo: RepositoryContext,
  severities: string[],
  detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = [],
): void {
  const broadCopy = dockerfile.instructions.find(
    (instruction) =>
      (instruction.keyword === "COPY" || instruction.keyword === "ADD") &&
      /(^|\s)\.(\s|$)/.test(instruction.value),
  );
  if (broadCopy === undefined) return;
  if (repo.hasDockerignore(dockerfile.path)) return;
  severities.push(Severity.Medium);
  detections.push({
    ruleId: "dockerfile.ignore.missing",
    file: dockerfile.path,
    line: broadCopy.line,
    snippet: broadCopy.raw,
    message: "Missing .dockerignore with broad COPY",
    severity: Severity.Medium,
  });
  observeDockerRule(ctx, {
    ruleId: "dockerfile.ignore.missing",
    subject: dockerfile.path,
    severity: Severity.Medium,
    confidence: "high",
    location: { file: dockerfile.path, line: broadCopy.line, snippet: broadCopy.raw },
    evidence: { instruction: broadCopy.raw },
  });
}

function reportSecretLayerHistoryObservations(
  ctx: RuleContext,
  dockerfile: ParsedDockerfile,
  severities: string[],
  detections: Array<{ ruleId: string; file: string; line: number; snippet: string; message: string; severity: string }> = [],
): void {
  const credentialLike = /(?:^|[\s/])(?:id_rsa|id_ed25519|.*\.pem|\.npmrc|\.netrc|service-account.*\.json)(?:\s|$)/i;
  for (let i = 0; i < dockerfile.instructions.length; i++) {
    const instruction = dockerfile.instructions[i]!;
    if (instruction.keyword !== "COPY" && instruction.keyword !== "ADD") continue;
    if (!credentialLike.test(instruction.value)) continue;
    const dest = instruction.value.trim().split(/\s+/).pop() ?? "";
    const base = dest.split("/").pop() ?? dest;
    const removedLater = dockerfile.instructions.slice(i + 1).some(
      (later) =>
        later.keyword === "RUN" &&
        new RegExp(`\\brm\\b[^\\n]*${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i").test(later.value),
    );
    if (!removedLater) continue;
    severities.push(Severity.High);
    detections.push({
      ruleId: "dockerfile.secret.rm-later-layer",
      file: dockerfile.path,
      line: instruction.line,
      snippet: instruction.raw,
      message: "Secret added then removed in a later layer",
      severity: Severity.High,
    });
    observeDockerRule(ctx, {
      ruleId: "dockerfile.secret.rm-later-layer",
      subject: dockerfile.path,
      severity: Severity.High,
      confidence: "medium",
      location: { file: dockerfile.path, line: instruction.line, snippet: instruction.raw },
      evidence: { instruction: instruction.raw },
    });
  }
}

function reportPositiveSignals(ctx: RuleContext, dockerfile: ParsedDockerfile): void {
  if (dockerfile.stages.length > 1) {
    ctx.review.positive({
      key: `dockerfile.multi-stage:${dockerfile.path}`,
      summary: `The Dockerfile uses a multi-stage build (${stageNames(dockerfile).join(", ")}).`,
      evidence: [{ file: dockerfile.path, line: dockerfile.stages[0].from.line }],
    });
  }

  const copyFrom = dockerfile.stages
    .find((stage) => stage.isFinal)
    ?.instructions.find((instruction) => instruction.keyword === "COPY" && /(?:^|\s)--from=/i.test(instruction.value));
  if (copyFrom !== undefined) {
    ctx.review.positive({
      key: `dockerfile.runtime.artifacts-only:${dockerfile.path}`,
      summary: "The runtime stage copies artifacts from an earlier stage instead of rebuilding the application.",
      evidence: [{ file: dockerfile.path, line: copyFrom.line }],
    });
  }

  const stageImages = dockerfile.stages.map((stage) => stage.image);
  if (stageImages.length > 0 && stageImages.every((image) => /^node:.*-slim(?:@|$)/i.test(image))) {
    ctx.review.positive({
      key: `dockerfile.slim-base:${dockerfile.path}`,
      summary: "The Dockerfile uses slim Node base images across its stages.",
    });
  }
}

function reportReviewObservations(ctx: RuleContext, dockerfile: ParsedDockerfile): void {
  if (dockerfile.stages.length >= 3 && dockerfile.stages.every((stage) => !/^stage-\d+$/.test(stage.name))) {
    ctx.review.observe({
      key: `dockerfile.stage-layout:${dockerfile.path}`,
      summary: `The Dockerfile defines ${stageNames(dockerfile).join(", ")} stages.`,
    });
  }
}

function reportOpinion(ctx: RuleContext, dockerfiles: ParsedDockerfile[], severities: string[]): void {
  const risk = riskFromSeverities(severities);
  if (dockerfiles.length === 0) {
    ctx.review.opinion({ ship: true, summary: "There is no Dockerfile to review in this repository." });
    return;
  }

  if (risk === "none") {
    ctx.review.opinion({ ship: true, summary: "I would ship this Dockerfile as-is. No material issues were identified." });
  } else if (risk === "low") {
    ctx.review.opinion({ ship: true, summary: "I would ship this Dockerfile as-is. The remaining recommendations are low-risk hardening improvements." });
  } else {
    ctx.review.opinion({ ship: false, summary: "I would address the runtime or security findings before shipping this image." });
  }
}

function riskFromSeverities(severities: string[]): "none" | "low" | "medium" | "high" | "critical" {
  if (severities.includes(Severity.Critical)) {
    return "critical";
  }
  if (severities.includes(Severity.High)) {
    return "high";
  }
  if (severities.includes(Severity.Medium)) {
    return "medium";
  }
  if (severities.includes(Severity.Low) || severities.includes(Severity.Info)) {
    return "low";
  }
  return "none";
}

async function walkRepository(repoPath: string, maxFiles = MAX_REPOSITORY_FILES): Promise<string[]> {
  const files: string[] = [];

  async function visit(directory: string): Promise<void> {
    if (files.length >= maxFiles) {
      return;
    }

    let entries;
    try {
      entries = await readdir(join(repoPath, directory), { withFileTypes: true });
    } catch {
      return;
    }

    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries.filter((candidate) => candidate.isFile())) {
      if (files.length >= maxFiles) {
        return;
      }

      const relativePath = directory === "" ? entry.name : join(directory, entry.name);
      files.push(toPosixPath(relativePath));
    }

    for (const entry of entries.filter((candidate) => candidate.isDirectory())) {
      if (files.length >= maxFiles) {
        return;
      }

      if (!SKIPPED_DIRECTORIES.has(entry.name)) {
        const relativePath = directory === "" ? entry.name : join(directory, entry.name);
        await visit(toPosixPath(relativePath));
      }
    }
  }

  await visit("");
  return files;
}

function parseDockerfile(source: string): DockerfileInstruction[] {
  const instructions: DockerfileInstruction[] = [];
  const lines = source.split(/\r?\n/);
  let current: { line: number; lines: string[] } | undefined;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    if (current === undefined && (trimmed.length === 0 || trimmed.startsWith("#"))) {
      continue;
    }

    if (current === undefined) {
      current = { line: index + 1, lines: [line] };
    } else {
      current.lines.push(line);
    }

    if (continuesInstruction(line)) {
      continue;
    }

    const raw = current.lines.join("\n");
    const match = raw.match(/^\s*([a-z]+)\s+(.*)$/is);
    if (match !== null) {
      instructions.push({
        keyword: match[1].toUpperCase(),
        value: stripContinuations(match[2]).trim(),
        line: current.line,
        raw,
      });
    }
    current = undefined;
  }

  return instructions;
}

function parseStages(instructions: DockerfileInstruction[]): DockerfileStage[] {
  const stages: DockerfileStage[] = [];
  let current: DockerfileStage | undefined;

  for (const instruction of instructions) {
    if (instruction.keyword === "FROM") {
      if (current !== undefined) {
        stages.push(current);
      }

      current = {
        name: parseStageName(instruction.value) ?? `stage-${stages.length}`,
        image: parseFromImage(instruction.value) ?? "unknown",
        from: instruction,
        instructions: [instruction],
        isFinal: false,
      };
    } else if (current !== undefined) {
      current.instructions.push(instruction);
    }
  }

  if (current !== undefined) {
    stages.push(current);
  }

  const final = stages[stages.length - 1];
  if (final !== undefined) {
    final.isFinal = true;
  }

  return stages;
}

function parseDockerignore(source: string): string[] {
  return source
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

function continuesInstruction(line: string): boolean {
  return /(^|[^\\])\\\s*$/.test(line);
}

function stripContinuations(value: string): string {
  return value.replace(/\\\r?\n/g, " ");
}

function parseFromImage(value: string): string | undefined {
  const tokens = shellLikeTokens(value);
  return tokens.find((token) => !token.startsWith("--") && token.toUpperCase() !== "AS");
}

function parseStageName(value: string): string | undefined {
  const tokens = shellLikeTokens(value);
  const asIndex = tokens.findIndex((token) => token.toUpperCase() === "AS");
  return asIndex === -1 ? undefined : tokens[asIndex + 1];
}

function variableNames(instruction: DockerfileInstruction): string[] {
  if (instruction.keyword === "ARG") {
    return [instruction.value.split("=", 1)[0].trim()].filter(Boolean);
  }

  const tokens = shellLikeTokens(instruction.value);
  if (tokens.length === 0) {
    return [];
  }

  return tokens[0].includes("=") ? tokens.map((token) => token.split("=", 1)[0]).filter(Boolean) : [tokens[0]];
}

function copiesWholeContext(value: string): boolean {
  const tokens = shellLikeTokens(value).filter((token) => !token.startsWith("--"));
  return tokens[0] === ".";
}

function shellLikeTokens(value: string): string[] {
  const tokens: string[] = [];
  const pattern = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'|(\S+)/g;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(value)) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3]);
  }

  return tokens;
}

function finalStageCopiesFromStage(dockerfile: ParsedDockerfile, stageName: string): boolean {
  const finalStage = dockerfile.stages.find((stage) => stage.isFinal);
  return finalStage?.instructions.some((instruction) => instruction.keyword === "COPY" && instruction.value.includes(`--from=${stageName}`)) ?? false;
}

function imageTag(image: string): string | undefined {
  const imageWithoutDigest = image.split("@", 1)[0];
  const parts = imageWithoutDigest.split("/");
  const lastSegment = parts[parts.length - 1] ?? "";
  const colonIndex = lastSegment.lastIndexOf(":");
  return colonIndex === -1 ? undefined : lastSegment.slice(colonIndex + 1);
}

function hasDigest(image: string): boolean {
  return /@sha256:[a-f0-9]{32,}$/i.test(image);
}

function isScratch(image: string): boolean {
  return image.toLowerCase() === "scratch";
}

function isRootUser(value: string): boolean {
  const user = value.trim().split(/\s+/, 1)[0].split(":", 1)[0].toLowerCase();
  return user === "root" || user === "0";
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function dockerignorePathFor(dockerfilePath: string): string {
  const directory = dirname(dockerfilePath);
  return directory === "." ? ".dockerignore" : join(directory, ".dockerignore");
}

function isIgnoredByDockerignore(path: string, entries: string[]): boolean {
  let ignored = false;
  for (const entry of entries) {
    const negated = entry.startsWith("!");
    const pattern = negated ? entry.slice(1) : entry;
    if (matchesDockerignorePattern(path, pattern)) {
      ignored = !negated;
    }
  }
  return ignored;
}

function matchesDockerignorePattern(path: string, pattern: string): boolean {
  const normalizedPattern = pattern.replace(/^\//, "").replace(/\/$/, "");
  if (normalizedPattern.length === 0) {
    return false;
  }

  if (normalizedPattern.includes("*")) {
    const source = normalizedPattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*\*/g, "\0")
      .replace(/\*/g, "[^/]*")
      .replace(/\0/g, ".*");
    return new RegExp(`(^|/)${source}($|/)`).test(path);
  }

  return path === normalizedPattern || path.startsWith(`${normalizedPattern}/`) || path.endsWith(`/${normalizedPattern}`);
}

function isDockerfilePath(path: string): boolean {
  const filename = path.split("/").pop() ?? "";
  return filename === "Dockerfile" || filename.startsWith("Dockerfile.") || filename.endsWith(".dockerfile");
}

function isLikelyUnneededInImage(path: string): boolean {
  return /(^|\/)(?:test|tests|fixtures|docs|examples|coverage|\.github)(\/|$)/i.test(path) || /\.(?:md|snap|map)$/i.test(path);
}

function isLikelySensitiveContextFile(path: string): boolean {
  return /(^|\/)(?:\.env|\.npmrc|\.pypirc|\.netrc|id_rsa|credentials|config\.json)$|\.pem$|\.key$/i.test(path);
}

function stageNames(dockerfile: ParsedDockerfile): string[] {
  return dockerfile.stages.map((stage) => stage.name);
}

function toPosixPath(path: string): string {
  return path.split(sep).join("/");
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) {
  await createApp().runFromEnvironment();
}
