import {cachedRequest} from './common.js';
// The legacy second argument is ignored for compatibility; credentials are Worker-only.
export function ransomwareLiveAdapter(query,_unused,options={}){return cachedRequest('Ransomware.live Pro',query,'',options)}
