import {cachedRequest} from './common.js';
export function ransomlookAdapter(query,options={}){return cachedRequest('RansomLook',query,'',{...options})}
