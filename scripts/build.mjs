import {cp,mkdir,copyFile,readFile,writeFile} from 'node:fs/promises';
await mkdir('dist',{recursive:true});
await Promise.all([copyFile('index.html','dist/index.html'),copyFile('styles.css','dist/styles.css'),cp('src','dist/src',{recursive:true})]);
const html=await readFile('dist/index.html','utf8');
const version=process.env.GITHUB_SHA?.slice(0,12)||Date.now().toString(36);
await writeFile('dist/index.html',html.replace('./src/app.js',`./src/app.js?v=${version}`));
console.log('Static production site copied to dist/');
