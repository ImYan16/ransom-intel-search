import {cp,mkdir,copyFile,readFile,writeFile,readdir} from 'node:fs/promises';
import {join} from 'node:path';
await mkdir('dist',{recursive:true});
await Promise.all([copyFile('index.html','dist/index.html'),copyFile('styles.css','dist/styles.css'),cp('src','dist/src',{recursive:true})]);
const html=await readFile('dist/index.html','utf8');
const version=process.env.GITHUB_SHA?.slice(0,12)||Date.now().toString(36);
await writeFile('dist/index.html',html.replace('./src/app.js',`./src/app.js?v=${version}`));
async function versionModules(dir){
 for(const entry of await readdir(dir,{withFileTypes:true})){
  const file=join(dir,entry.name);
  if(entry.isDirectory()){await versionModules(file);continue;}
  if(!file.endsWith('.js'))continue;
  const source=await readFile(file,'utf8');
  await writeFile(file,source.replace(/(from\s+['"])(\.\.\/|\.\/)([^'"]+\.js)(['"])/g,`$1$2$3?v=${version}$4`));
 }
}
await versionModules('dist/src');
console.log('Static production site copied to dist/');
