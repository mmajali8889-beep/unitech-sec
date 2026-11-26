// End-to-end browser workflow against the real stack (API + agent + built frontend).
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)("playwright");
import fs from "node:fs";

const [, , base, user, pass, projectPath, shotDir] = process.argv;
const NEW_PASS = "E2eNewPassw0rdXyz";
const results = [];
const ok = (name, cond, extra = "") => { results.push({ name, pass: !!cond, extra }); console.log(`${cond ? "PASS" : "FAIL"}  ${name} ${extra}`); if (!cond) process.exitCode = 1; };
fs.mkdirSync(shotDir, { recursive: true });

const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1360, height: 900 } })).newPage();
const consoleErrors = [];
page.on("pageerror", (e) => consoleErrors.push(String(e)));
const shot = (n) => page.screenshot({ path: `${shotDir}/${n}.png` });

await page.goto(base);
ok("login page renders", await page.getByRole("button", { name: "Sign in" }).isVisible());
await page.getByLabel("Username").fill(user); await page.getByLabel("Password").fill("wrong-password");
await page.getByRole("button", { name: "Sign in" }).click();
await page.getByText("invalid credentials").waitFor();
ok("bad credentials rejected", true);
await page.getByLabel("Password").fill(pass); await page.getByRole("button", { name: "Sign in" }).click();
await page.getByText("You must change your password").waitFor({ timeout: 8000 }).catch(async (e) => { await shot("debug-login"); console.log(await page.locator("body").innerText()); throw e; });
ok("forced password change", true);
await page.getByLabel("Current password").fill(pass); await page.getByLabel("New password").fill(NEW_PASS);
await page.getByRole("button", { name: "Save" }).click();
await page.getByRole("heading", { name: "Executive Dashboard" }).waitFor();
ok("dashboard after password change", true);
await shot("01-dashboard");

// register project through approved-directory browser
await page.getByRole("link", { name: "Projects" }).click();
await page.getByRole("button", { name: "Register" }).first().click();
await page.getByLabel("Name").fill("vulnapp");
await page.getByLabel("Path").fill(projectPath);
await page.getByRole("dialog").getByRole("button", { name: "Register" }).click();
await page.getByRole("cell", { name: "vulnapp", exact: true }).waitFor({ timeout: 8000 }).catch(async (e) => { await shot("debug-reg"); console.log(await page.locator("body").innerText()); throw e; });
ok("project registered", true);

// path outside approved roots must be rejected by the backend
await page.getByRole("button", { name: "Register" }).first().click();
await page.getByLabel("Name").fill("outside"); await page.getByLabel("Path").fill("/etc");
await page.getByRole("dialog").getByRole("button", { name: "Register" }).click();
await page.getByText(/outside the approved/).waitFor();
ok("unapproved path rejected", true);
await page.keyboard.press("Escape");

// scan center -> live monitor -> completed
await page.getByRole("link", { name: "Scan Center" }).click();
await page.locator("select").first().selectOption({ label: "vulnapp" });
await page.getByRole("button", { name: "Start scan" }).click();
await page.getByRole("heading", { name: "Live Scan Monitor" }).waitFor();
await page.getByText("Completed", { exact: true }).first().waitFor({ timeout: 60000 });
ok("scan reached Completed with live events", await page.getByText("[persist]").isVisible());
await shot("02-live");

// findings: filter and detail with redacted snippet
await page.getByRole("link", { name: "Vulnerability Management" }).first().click();
await page.getByRole("cell", { name: "TNT002" }).first().waitFor();
const body = await page.locator("body").innerText();
ok("no raw secret rendered in UI", !/Sup3rS3cretPassw0rd|AKIAIOSFODNN7EXAMPLE|hunter2pass/.test(body));
await page.getByRole("cell", { name: "TNT002" }).first().click();
ok("finding detail shows remediation", await page.getByText("Remediation:").isVisible());
await shot("03-finding");
await page.keyboard.press("Escape");
await page.getByRole("link", { name: "Secrets Detection" }).click();
await page.getByRole("cell", { name: "SEC002" }).first().waitFor();
ok("secrets page lists SEC002", true);
await page.getByRole("link", { name: "Docker Security" }).click();
await page.getByRole("cell", { name: "DKR007" }).first().waitFor();
ok("docker page lists DKR007", true);

// report generation + real download
await page.getByRole("link", { name: "Reports Center" }).click();
await page.locator("select").first().selectOption({ index: 1 });
await page.locator("select").nth(1).selectOption("sarif");
await page.getByRole("button", { name: "Generate" }).click();
await page.getByRole("cell", { name: "sarif", exact: true }).first().waitFor();
const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download" }).first().click()]);
const f = `${shotDir}/report.sarif`; await dl.saveAs(f);
ok("SARIF report downloaded & valid", JSON.parse(fs.readFileSync(f, "utf8")).version === "2.1.0");

// BEKO page: Ollama is offline in this environment -> honest status, scanner data intact
await page.getByRole("link", { name: "BEKO AI Analysis" }).click();
await page.getByText("offline").first().waitFor();
ok("BEKO shows Ollama offline honestly", await page.getByText("UNVERIFIED").first().isVisible());

// audit + health
await page.getByRole("link", { name: "Audit Logs" }).click();
await page.getByRole("button", { name: "Verify chain" }).click();
await page.getByText(/chain intact/).waitFor();
ok("audit chain verifies", true);
await page.getByRole("link", { name: "System Health" }).click();
await page.getByText("online", { exact: true }).first().waitFor();
ok("agent online in health page", true);
await page.getByRole("link", { name: "Security Engines" }).click();
await page.getByText("pip-audit").first().waitFor();
ok("engines page marks CVE scanners unavailable", (await page.locator("tr", { hasText: "pip-audit" }).first().innerText()).includes("✗"));

// Arabic RTL + light theme
await page.getByRole("button", { name: "Language" }).click();
ok("RTL applied for Arabic", (await page.evaluate(() => document.documentElement.dir)) === "rtl");
await page.getByRole("link", { name: "لوحة الأمن التنفيذية" }).click();
await page.getByRole("heading", { name: "لوحة الأمن التنفيذية" }).waitFor();
await page.waitForTimeout(600);
await shot("04-arabic-rtl");
await page.getByRole("button", { name: "السمة" }).click();
ok("light theme toggles", !(await page.evaluate(() => document.documentElement.classList.contains("dark"))));
await shot("05-light");
await page.setViewportSize({ width: 390, height: 800 });
ok("mobile: no horizontal overflow", await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
await shot("06-mobile");

ok("no uncaught page errors", consoleErrors.length === 0, consoleErrors.join(" | "));
await browser.close();
fs.writeFileSync(`${shotDir}/results.json`, JSON.stringify(results, null, 2));
console.log(`\n${results.filter((r) => r.pass).length}/${results.length} checks passed`);
