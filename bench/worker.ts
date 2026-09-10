/** Runs a single benchmark case and prints its statistics as JSON on stdout;
 * spawned once per case and run by the CLI */
import { CaseSpec, Timing, measure } from './harness';


async function main(): Promise<void> {
  const { spec, timing }: { spec: CaseSpec, timing: Timing } = JSON.parse(process.argv[2]);
  const result = await measure(spec, timing);
  process.stdout.write(JSON.stringify(result));
}


main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
