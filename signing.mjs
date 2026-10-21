import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

export function validateSigning(value) {
  if (!value) return null;
  if (!/^[a-f0-9]{64}$/.test(value.certificateSha256 ?? '') || !/^[1-9][0-9]{0,7}$/.test(value.build ?? '') || Number(value.build)<2 ||
      typeof value.password !== 'string' || value.password.length < 32 ||
      ![value.p12Base64,value.profileBase64].every(s => typeof s === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(s) && Buffer.from(s,'base64').length > 1000) ||
      value.api?.issuerId !== '2fdcb9e9-28e1-4012-8eed-9ec033d3ec74' || !/^[A-Z0-9]{10}$/.test(value.api?.keyId ?? '') ||
      !value.api?.privateKey?.startsWith('-----BEGIN PRIVATE KEY-----')) throw Error('Invalid owner signing request');
  return value;
}

export function archiveSigningArguments(identity,name,build,keychain) {
  // The app target expands this custom setting. Dependency bundles never
  // receive an application provisioning profile.
  return ['CURRENT_PROJECT_VERSION='+build,'DEVELOPMENT_TEAM=UWPUJ24CNA','INDIECRM_PROFILE_SPECIFIER='+name,'CODE_SIGN_STYLE=Manual','CODE_SIGN_IDENTITY='+identity,'CODE_SIGNING_ALLOWED=YES',...(keychain?['OTHER_CODE_SIGN_FLAGS=--keychain '+keychain]:[])];
}

export function signingSetup({request,root,env,run,output}) {
  const data=validateSigning(request.signing);
  if(!data)return null;
  const directory=path.join(root,'private-signing');fs.mkdirSync(directory,{mode:0o700});
  const profile=path.join(directory,'app.mobileprovision'),p12=path.join(directory,'identity.p12'),keychain=path.join(directory,'signing.keychain-db');
  fs.writeFileSync(profile,Buffer.from(data.profileBase64,'base64'),{mode:0o600});
  fs.writeFileSync(p12,Buffer.from(data.p12Base64,'base64'),{mode:0o600});
  const decoded=spawnSync('security',['cms','-D','-i',profile],{env,encoding:'utf8',timeout:30000});
  if(decoded.status!==0)throw Error('Apple profile decode failed');
  fs.writeFileSync(path.join(directory,'profile.plist'),decoded.stdout,{mode:0o600});
  const check=spawnSync('python3',['-c',`
import sys,plistlib,datetime,hashlib,json,pathlib
p=plistlib.loads(pathlib.Path(sys.argv[1]).read_bytes())
assert p['TeamIdentifier']==['UWPUJ24CNA']
assert p['Entitlements']['application-identifier']=='UWPUJ24CNA.app.indiecrm.ios'
assert p['Entitlements'].get('get-task-allow') is False
assert p['Entitlements'].get('com.apple.developer.associated-domains')
assert not p.get('ProvisionedDevices') and not p.get('ProvisionsAllDevices')
assert p['ExpirationDate']>datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
certs=[c for c in p['DeveloperCertificates'] if hashlib.sha256(c).hexdigest()==sys.argv[2]]
assert len(certs)==1
print(json.dumps({'uuid':p['UUID'],'name':p['Name'],'identity':hashlib.sha1(certs[0]).hexdigest().upper()}))
`,path.join(directory,'profile.plist'),data.certificateSha256],{env,encoding:'utf8',timeout:30000});
  if(check.status!==0)throw Error('Apple signing scope differs');
  const metadata=JSON.parse(check.stdout);
  if(!/^[A-Fa-f0-9-]{36}$/.test(metadata.uuid)||!metadata.name||/[\r\n\t]/.test(metadata.name)||!/^[A-F0-9]{40}$/.test(metadata.identity))throw Error('Invalid Apple signing metadata');
  const profiles=path.join(env.HOME,'Library/MobileDevice/Provisioning Profiles');fs.mkdirSync(profiles,{recursive:true});
  const installed=path.join(profiles,metadata.uuid+'.mobileprovision');fs.copyFileSync(profile,installed,fs.constants.COPYFILE_EXCL);
  run('create-signing-keychain','security',['create-keychain','-p',data.password,keychain]);
  run('keep-signing-keychain-unlocked','security',['set-keychain-settings','-lut','21600',keychain]);
  run('unlock-signing-keychain','security',['unlock-keychain','-p',data.password,keychain]);
  run('import-signing-identity','security',['import',p12,'-P',data.password,'-k',keychain,'-t','cert','-f','pkcs12','-A']);
  run('configure-signing-keychain','security',['set-key-partition-list','-S','apple-tool:,apple:,codesign:','-k',data.password,keychain]);
  run('select-signing-keychain','security',['list-keychains','-d','user','-s',keychain,path.join(env.HOME,'Library/Keychains/login.keychain-db')]);
  const options={method:'app-store-connect',destination:'export',teamID:'UWPUJ24CNA',signingStyle:'manual',signingCertificate:metadata.identity,provisioningProfiles:{'app.indiecrm.ios':metadata.uuid},manageAppVersionAndBuildNumber:false,uploadSymbols:true};
  fs.writeFileSync(path.join(directory,'export.json'),JSON.stringify(options));
  const plist=spawnSync('python3',['-c',"import sys,json,plistlib,pathlib;pathlib.Path(sys.argv[2]).write_bytes(plistlib.dumps(json.loads(pathlib.Path(sys.argv[1]).read_text())))",path.join(directory,'export.json'),path.join(directory,'ExportOptions.plist')],{env,timeout:30000});
  if(plist.status!==0)throw Error('Export settings unavailable');
  const proof={signed:false,uploaded:false,build:data.build,certificateSha256:data.certificateSha256,profileId:metadata.uuid};
  return {
    proof,
    archiveArgs:archiveSigningArguments(metadata.identity,metadata.name,data.build,keychain),
    beforeArchive() {
      run('unlock-signing-before-archive','security',['unlock-keychain','-p',data.password,keychain]);
    },
    finish(archive) {
      run('verify-device-signature','codesign',['--verify','--deep','--strict',path.join(archive,'Products/Applications/IndieCRM.app')]);
      const exportPath=path.join(directory,'export');
      run('export-app-store-ipa','xcodebuild',['-exportArchive','-archivePath',archive,'-exportPath',exportPath,'-exportOptionsPlist',path.join(directory,'ExportOptions.plist')]);
      const ipa=path.join(exportPath,'IndieCRM.ipa');if(!fs.statSync(ipa).size)throw Error('Signed IPA unavailable');
      fs.copyFileSync(ipa,path.join(output,'IndieCRM.ipa'));
      proof.signed=true;
      fs.writeFileSync(path.join(directory,'AuthKey_'+data.api.keyId+'.p8'),data.api.privateKey,{mode:0o600});
      env.API_PRIVATE_KEYS_DIR=directory;
      run('upload-to-apple','xcrun',['altool','--upload-app','--type','ios','--file',ipa,'--apiKey',data.api.keyId,'--apiIssuer',data.api.issuerId,'--output-format','json'],12*60_000);
      delete env.API_PRIVATE_KEYS_DIR;
      proof.uploaded=true;
      return proof;
    },
    cleanup() {
      spawnSync('security',['delete-keychain',keychain],{env,stdio:'ignore',timeout:30000});
      fs.rmSync(installed,{force:true});fs.rmSync(directory,{recursive:true,force:true});
    }
  };
}
