const PACKAGE_NAME = "@dorigjo/besa";
const REPOSITORY = "dorigjo/besa";
const OWNER = "dorigjo";

function isoDate(daysAgo) {
  const date = new Date();
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCDate(date.getUTCDate() - daysAgo);
  return date.toISOString().slice(0, 10);
}

async function fetchJson(url, headers = {}) {
  const response = await fetch(url, {
    headers,
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} from ${url}`);
  }
  return response.json();
}

function npmUrl(start, end) {
  return `https://api.npmjs.org/downloads/point/${start}:${end}/${encodeURIComponent(PACKAGE_NAME)}`;
}

function githubHeaders() {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "besa-traction-report",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return headers;
}

function growth(current, previous) {
  if (previous === 0) return current === 0 ? "0.0%" : "n/a (previous period was zero)";
  const percent = ((current - previous) / previous) * 100;
  return `${percent >= 0 ? "+" : ""}${percent.toFixed(1)}%`;
}

async function main() {
  const latestStart = isoDate(7);
  const latestEnd = isoDate(1);
  const previousStart = isoDate(14);
  const previousEnd = isoDate(8);
  const monthStart = isoDate(30);
  const github = githubHeaders();
  const query = encodeURIComponent(`repo:${REPOSITORY} is:issue is:open`);
  const externalQuery = encodeURIComponent(
    `repo:${REPOSITORY} is:issue is:open -author:${OWNER}`,
  );

  const [latest, previous, month, repository, issues, externalIssues, release] =
    await Promise.all([
      fetchJson(npmUrl(latestStart, latestEnd)),
      fetchJson(npmUrl(previousStart, previousEnd)),
      fetchJson(npmUrl(monthStart, latestEnd)),
      fetchJson(`https://api.github.com/repos/${REPOSITORY}`, github),
      fetchJson(`https://api.github.com/search/issues?q=${query}`, github),
      fetchJson(`https://api.github.com/search/issues?q=${externalQuery}`, github),
      fetchJson(`https://api.github.com/repos/${REPOSITORY}/releases/latest`, github),
    ]);

  console.log("BESA TRACTION");
  console.log(`period end: ${latestEnd} UTC`);
  console.log("");
  console.log(`npm 7d: ${latest.downloads}`);
  console.log(`npm previous 7d: ${previous.downloads}`);
  console.log(`growth: ${growth(latest.downloads, previous.downloads)}`);
  console.log(`npm 30d: ${month.downloads}`);
  console.log("");
  console.log(`stars: ${repository.stargazers_count}`);
  console.log(`forks: ${repository.forks_count}`);
  console.log(`open issues: ${issues.total_count}`);
  console.log(`external issues: ${externalIssues.total_count}`);
  console.log(`latest release: ${release.tag_name} (${release.published_at})`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Traction report failed: ${message}`);
  process.exitCode = 1;
});
