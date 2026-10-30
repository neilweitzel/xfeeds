// The probe writes data, never executable JavaScript or interpolated workflow code.
module.exports = async ({ github, context, core, report }) => {
  const title = "xfeeds: heartbeat health check failed";
  const legacyTitle = "xfeeds: feed has stopped updating";
  const repo = { owner: context.repo.owner, repo: context.repo.repo };
  const runUrl = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${context.runId}`;
  const issues = await github.paginate(github.rest.issues.listForRepo, {
    ...repo, state: "open", labels: "automated", per_page: 100,
  });
  const matches = issues.filter(i => !i.pull_request && [title, legacyTitle].includes(i.title));
  const age = check => check.age_hours === null ? "unknown" : `${check.age_hours.toFixed(1)}h`;
  const row = (name, check) =>
    `| ${name} | ${check.state} | ${age(check)} | ${check.timestamp ?? "unknown"} |`;

  if (!report.unhealthy) {
    for (const issue of matches) {
      await github.rest.issues.createComment({
        ...repo, issue_number: issue.number,
        body: `Recovered: both manifests are reachable, valid, and fresh `
          + `(committed ${age(report.repo)}, published ${age(report.pages)}). `
          + `Closing automatically.\n\nRun: ${runUrl}`,
      });
      await github.rest.issues.update({ ...repo, issue_number: issue.number, state: "closed" });
    }
    return;
  }

  // Failure remains visible even if fetching supplementary history or posting fails.
  core.setFailed(report.diagnosis);
  let runs = "Refresh history unavailable; check the Actions tab.";
  try {
    const res = await github.rest.actions.listWorkflowRuns({
      ...repo, workflow_id: "update-feeds.yml", per_page: 6,
    });
    runs = res.data.workflow_runs.map(r =>
      `- \`${r.status}/${r.conclusion ?? "n/a"}\` ${r.created_at} (${r.event})`
    ).join("\n") || "- no runs found";
  } catch {
    core.warning("Could not fetch supplementary refresh history.");
  }
  const body = [
    "A heartbeat health check failed. Unavailable or invalid data has unknown age, not stale age.",
    "", `**Diagnosis:** ${report.diagnosis}`, "",
    `Freshness limit: ${report.max_age_hours}h. Checked: ${report.checked_at}.`, "",
    "| Check | State | Age | Timestamp |", "|---|---|---|---|",
    row("Committed feeds/manifest.json", report.repo),
    row("Published Pages manifest.json", report.pages),
    "", "**Pages request attempts:**", ...report.attempts.map(item => `- ${item}`),
    "", "**Recent Update feeds runs:**", runs, "", `Run: ${runUrl}`,
  ].join("\n");
  if (matches.length) {
    // Migrate the old incident in place instead of creating an unrelated duplicate.
    await github.rest.issues.update({
      ...repo, issue_number: matches[0].number, title, body,
    });
    await github.rest.issues.createComment({
      ...repo, issue_number: matches[0].number, body,
    });
  } else {
    await github.rest.issues.create({ ...repo, title, body, labels: ["automated"] });
  }
};
