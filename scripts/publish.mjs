import { spawnSync } from "child_process";
import { readFileSync } from "fs";
import inquirer from "inquirer";
const prompt = inquirer.createPromptModule();
// ask the user if they want to bump the version using commander npm package
const { bump } = await prompt([
  {
    type: "list",
    name: "bump",
    message: "Do you want to bump the version?",
    choices: ["yes", "no"],
  },
]);
// if they do, ask them if they want a patch, minor, or major
if (bump === "yes") {
  const { version } = await prompt([
    {
      type: "list",
      name: "version",
      message: "What version do you want to bump?",
      choices: ["patch", "minor", "major"],
    },
  ]);
  // if spawnsync fails throw error
  console.log("Bumping version...");  
  if (spawnSync("npm", ["version", version, '--no-git-tag-version'], { stdio: "inherit" }).status !== 0) {
    throw new Error("Failed to bump version");
  }
}

// run build
// if spawnsync fails throw error
console.log("Building...");
if (spawnSync("npm", ["run", "build"], { stdio: "inherit" }).status !== 0) {
  throw new Error("Failed to build");
}

// ask the user for npm token
const { token } = await prompt([
  {
    type: "input",
    name: "token",
    message: "What is your npm token?",
  },
]);
// publish from the repo root; "files" in package.json limits the tarball to dist/
// ask the user if they want to do a dry run
const { dryRun } = await prompt([
  {
    type: "list",
    name: "dryRun",
    message: "Do you want to do a dry run?",
    choices: ["yes", "no"],
  },
]);
// if dry run 
if (dryRun === "yes") {
  console.log("Dry running publish...");
  const { status } = spawnSync("npm", ["publish", "--dry-run", "--access", "public", "--registry", "https://registry.npmjs.org"], {
    stdio: "inherit",
    env: {
      ...process.env,
      NPM_TOKEN: token,
    },
  });
  if (status !== 0) {
    throw new Error("Failed to dry run publish");
  }
} else {
  console.log("Publishing...");
  spawnSync("npm", ["publish", "--access", "public", "--registry", "https://registry.npmjs.org"], {
    stdio: "inherit",
    env: {
      ...process.env,
      NPM_TOKEN: token,
    },
  });
}
const packageJson = JSON.parse(readFileSync("package.json").toString());
// log the commands required to commit the files, tag the release and push to github
console.log(`
  git add .
  git commit -m "chore: publish"
  git tag -a v${packageJson.version} -m "chore: publish"
  git push origin develop
  git push origin --tags
`);

