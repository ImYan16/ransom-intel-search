import {cp,mkdir,copyFile} from 'node:fs/promises';
await mkdir('dist',{recursive:true});
await Promise.all([copyFile('index.html','dist/index.html'),copyFile('styles.css','dist/styles.css'),cp('src','dist/src',{recursive:true})]);
console.log('Static production site copied to dist/');
