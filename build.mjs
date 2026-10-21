import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {signingSetup} from './signing.mjs';

process.umask(0o077);
const root = process.env.PRIVATE_BUILD_ROOT;
const sha = process.env.EXPECTED_SOURCE_SHA;
if (!root || !/^[a-f0-9]{40}$/.test(sha ?? '')) throw Error('Invalid build identity');
const source = path.join(root, 'source');
const output = path.join(root, 'output');
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
const log = fs.openSync(path.join(output, 'build.log'), 'a', 0o600);
const env = Object.fromEntries(['PATH','HOME','USER','LOGNAME','TMPDIR','LANG','DEVELOPER_DIR'].flatMap(k => process.env[k] ? [[k,process.env[k]]] : []));
env.CI = 'true';
env.HOMEBREW_NO_AUTO_UPDATE = '1';
env.HOMEBREW_NO_INSTALL_CLEANUP = '1';
const steps = [];
function run(phase, command, args, timeout = 20 * 60_000) {
  const result = spawnSync(command,args,{cwd:path.join(source,'ios'),env,stdio:['ignore',log,log],timeout});
  steps.push({phase,passed:!result.error && result.status===0,exitCode:result.status});
  if (!steps.at(-1).passed) throw Error('Private build failed');
  console.log('Completed '+phase);
  return result;
}
let passed = false;
let signing;
let distribution={signed:false,uploaded:false};
try {
  const request = JSON.parse(fs.readFileSync(path.join(root,'request.json')));
  if (request.repository !== 'danielsinewe/indiecrm' || request.sourceSha !== sha || request.bundleId !== 'app.indiecrm.ios') throw Error('Source identity differs');
  for (const [file,digest] of Object.entries(request.files)) {
    if (!file.startsWith('ios/') || file.includes('..') || !/^[a-f0-9]{64}$/.test(digest)) throw Error('Invalid source manifest');
    if (createHash('sha256').update(fs.readFileSync(path.join(source,file))).digest('hex') !== digest) throw Error('Source checksum differs');
  }
  const spec=fs.readFileSync(path.join(source,'ios/project.yml'),'utf8');
  if (!spec.includes('app.indiecrm.ios') || !spec.includes('UWPUJ24CNA')) throw Error('Apple identity differs');
  run('install-project-generator','brew',['install','xcodegen']);
  run('generate-project','xcodegen',['generate']);
  signing=signingSetup({request,root,env,run,output});
  if(signing)distribution=signing.proof;
  const devices=spawnSync('xcrun',['simctl','list','devices','available','--json'],{env,encoding:'utf8',timeout:30_000});
  const available=Object.values(JSON.parse(devices.stdout).devices).flat().filter(d=>d.isAvailable&&/iPhone/.test(d.name));
  const simulator=available.find(d=>/Pro Max/.test(d.name))??available[0];
  if(!simulator)throw Error('No iPhone simulator available');
  run('native-tests','xcodebuild',['test','-project','IndieCRM.xcodeproj','-scheme','IndieCRM','-destination','platform=iOS Simulator,id='+simulator.udid,'-derivedDataPath','build/DerivedData','-resultBundlePath','build/Tests.xcresult','CODE_SIGN_IDENTITY=-','CODE_SIGNING_ALLOWED=YES','-parallel-testing-enabled','NO']);
  run('device-archive','xcodebuild',['archive','-project','IndieCRM.xcodeproj','-scheme','IndieCRM','-configuration','Release','-destination','generic/platform=iOS','-archivePath','build/IndieCRM.xcarchive',...(signing?.archiveArgs??['CODE_SIGNING_ALLOWED=NO'])]);
  const summary=spawnSync('xcrun',['xcresulttool','get','test-results','summary','--path',path.join(source,'ios/build/Tests.xcresult')],{env,encoding:'utf8',timeout:60_000});
  if(summary.status!==0)throw Error('Test summary unavailable');
  fs.writeFileSync(path.join(output,'tests.json'),summary.stdout);
  const tests=JSON.parse(summary.stdout);
  if(tests.failedTests!==0||tests.passedTests<14)throw Error('Native tests incomplete');
  fs.cpSync(path.join(source,'ios/build/IndieCRM.xcarchive'),path.join(output,'IndieCRM.xcarchive'),{recursive:true});
  if(signing)distribution=signing.finish(path.join(source,'ios/build/IndieCRM.xcarchive'));
  passed=true;
} catch {
  console.error('Native verification failed. Diagnostics remain encrypted.');
  process.exitCode=1;
} finally {
  signing?.cleanup();
  fs.closeSync(log);
  fs.writeFileSync(path.join(output,'result.json'),JSON.stringify({repository:'danielsinewe/indiecrm',sourceSha:sha,bundleId:'app.indiecrm.ios',teamId:'UWPUJ24CNA',passed,...distribution,steps,runId:process.env.GITHUB_RUN_ID},null,2)+'\n');
}
