import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const articlePath = join(root, "articles/github-actions-security-checklist/index.html");
const requiredCrawlers = [
  "GPTBot",
  "ChatGPT-User",
  "OAI-SearchBot",
  "ClaudeBot",
  "anthropic-ai",
  "Claude-Web",
  "PerplexityBot",
  "Perplexity-User",
  "Google-Extended",
  "GoogleOther",
  "Applebot-Extended",
  "Amazonbot",
  "CCBot",
  "Bytespider",
  "Diffbot",
  "FacebookBot",
  "Meta-ExternalAgent",
  "Meta-ExternalFetcher",
  "cohere-ai",
  "YouBot",
  "DuckAssistBot"
];

const citationUrls = [
  "https://docs.github.com/en/actions/reference/security/secure-use",
  "https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions",
  "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication",
  "https://github.com/ossf/scorecard/blob/main/docs/checks.md",
  "https://commons.wikimedia.org/wiki/File:AlphaGo_computer_rack.jpg"
];
const blockedPatterns = [
  new RegExp(`\\b${"D" + "om"}\\b`, "i"),
  new RegExp(`${"pay" + "pal"}`, "i"),
  new RegExp(`${"AI" + "-origin"}`, "i"),
  new RegExp(`${"AI" + "-built"}`, "i"),
  new RegExp(`${"dvo" + "ltolina"}`, "i"),
  new RegExp(`${"GUM" + "ROAD PASSWORD"}`, "i"),
  new RegExp(`${"DRAFT" + "_URL"}`, "i"),
  new RegExp(`${"TO" + "DO"}`, "i"),
  new RegExp(`${"FIX" + "ME"}`, "i")
];

const fail = (message) => {
  throw new Error(message);
};

const read = (path) => readFile(path, "utf8");

async function files(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    if (entry.isDirectory()) out.push(...await files(path));
    else out.push(path);
  }
  return out;
}

function betweenAll(source, start, end) {
  const matches = [];
  let offset = 0;
  while (true) {
    const from = source.indexOf(start, offset);
    if (from === -1) break;
    const to = source.indexOf(end, from + start.length);
    if (to === -1) break;
    matches.push(source.slice(from + start.length, to));
    offset = to + end.length;
  }
  return matches;
}

async function assertFetchable(url) {
  const response = await fetch(url, {
    method: "GET",
    redirect: "follow",
    headers: { "user-agent": "PipelineProofAudit/1.0" }
  });
  if (!(response.status >= 200 && response.status < 400)) {
    fail(`${url} returned ${response.status}`);
  }
}

const cname = await read(join(root, "CNAME"));
if (cname !== "dsotn.com\n") fail("CNAME must contain exactly dsotn.com plus trailing newline");

const robots = await read(join(root, "robots.txt"));
for (const crawler of requiredCrawlers) {
  if (!robots.includes(`User-agent: ${crawler}`)) fail(`robots.txt missing ${crawler}`);
}

const allFiles = await files(root);
for (const path of allFiles) {
  if (!/\.(html|md|txt|xml|json|css|mjs)$/.test(path)) continue;
  const text = await read(path);
  if (blockedPatterns.some((pattern) => pattern.test(text))) {
    fail(`forbidden public text in ${relative(root, path)}`);
  }
}

const article = await read(articlePath);
const h1Count = (article.match(/<h1\b/g) || []).length;
if (h1Count !== 1) fail("article must have exactly one h1");

const title = article.match(/<title>([^<]+)<\/title>/)?.[1] ?? "";
if (title.length < 50 || title.length > 60) fail(`article title length is ${title.length}`);

const description = article.match(/<meta name="description" content="([^"]+)">/)?.[1] ?? "";
if (description.length < 140 || description.length > 160) {
  fail(`article meta description length is ${description.length}`);
}

if (!article.includes('<link rel="canonical" href="https://dsotn.com/articles/github-actions-security-checklist/">')) {
  fail("article canonical missing or wrong");
}

if (!article.includes("Pipeline Proof Editorial")) fail("organization byline missing");
if (article.includes('"@type": "Person"')) fail("Person schema is not allowed");
if (!article.includes("This article is informational engineering guidance")) fail("body disclaimer missing");
if (!article.includes('id="key-takeaways"')) fail("key takeaways missing");
if (!article.includes('"@type": "BreadcrumbList"')) fail("BreadcrumbList JSON-LD missing");

for (const block of betweenAll(article, '<script type="application/ld+json">', "</script>")) {
  JSON.parse(block);
}

const heroStat = await stat(join(root, "assets/images/articles/github-actions-security-checklist.jpg"));
if (heroStat.size < 100_000) fail("hero image looks missing or too small");

const credits = await read(join(root, "CREDITS.md"));
if (!credits.includes("https://commons.wikimedia.org/wiki/File:AlphaGo_computer_rack.jpg")) {
  fail("CREDITS.md missing image source URL");
}

for (const url of citationUrls) {
  await assertFetchable(url);
}

console.log("audit passed");
