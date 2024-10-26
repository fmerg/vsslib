import { spawnSync } from "child_process";
import { readFileSync, writeFileSync } from "fs";
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

// copy package.json to dist without devDependencies
console.log("Copying package.json to dist...");
const packageJson = JSON.parse(readFileSync("package.json").toString());
const distPackageJson = {
  ...packageJson,
  devDependencies: {},
  scripts: {},
};
writeFileSync("dist/package.json", JSON.stringify(distPackageJson, null, 2));
// copy README.md to dist
console.log("Copying README.md to dist...");
writeFileSync("dist/README.md", readFileSync("README.md").toString());
// ask the user for npm token
const { token } = await prompt([
  {
    type: "input",
    name: "token",
    message: "What is your npm token?",
  },
]);
// cd to dist and publish
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
    cwd: "dist",
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
    cwd: "dist",
    env: {
      ...process.env,
      NPM_TOKEN: token,
    },
  });
}
// log the commands required to commit the files, tag the release and push to github
console.log(`
  git add .
  git commit -m "chore: publish"
  git tag -a v${packageJson.version} -m "chore: publish"
  git push origin develop
  git push origin --tags
`);

