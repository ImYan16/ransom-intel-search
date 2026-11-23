import {getJson,arrayResponse,normalize} from './shared.js';
const SOURCE='RansomFeed';
const fields={name:['victim','name'],website:['website'],country:['country','country_name','country_code'],industry:['work_sector','sector'],group:['gang'],attack:['date'],discovered:['date_human'],description:['description','victim_notes'],screenshot:['screenshot','screen'],url:['record_url','url','link'],urlBase:'https://ransomfeed.it',id:['id']};

function normalizeRows(rows){
 return rows.map(row=>{
  const recordUrl=row.id==null?null:`/?page=post_details&id_post=${encodeURIComponent(String(row.id))}`;
  const normalized=normalize({...row,record_url:recordUrl},SOURCE,fields);
  if(normalized)normalized.raw_source_data=row;
  return normalized;
 }).filter(Boolean);
}

function normalizeSearchText(value){
 return value.normalize('NFKC').toLowerCase().replace(/\s+/g,' ').trim();
}

function matchesSearch(row,query){
 const term=normalizeSearchText(query);
 return [row.search_text,row.victim,row.gang,row.country,row.website,row.admin_notes,row.description]
  .some(value=>typeof value==='string'&&normalizeSearchText(value).includes(term));
}

function matchesDocumentedSearch(row,query){
 const term=normalizeSearchText(query);
 return ['victim','description','city','region','work_sector']
  .some(field=>typeof row[field]==='string'&&normalizeSearchText(row[field]).includes(term));
}

async function siteSearch(query){
 const url=new URL('https://ransomfeed.it/search-results-api.php');
 url.searchParams.set('q',query);
 url.searchParams.set('group','all');
 const data=await getJson(url.href);
 if(data?.status!=='ok'||!Array.isArray(data.rows))throw Object.assign(new Error('Unexpected site-search response schema'),{kind:'invalid'});
 return normalizeRows(data.rows.filter(row=>matchesSearch(row,query)));
}

function htmlText(value){
 return value.replace(/<br\s*\/?>/gi,' ').replace(/<\/(?:div|p|li)>/gi,' ')
  .replace(/<[^>]*>/g,' ').replace(/&nbsp;/gi,' ').replace(/&amp;/gi,'&')
  .replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/&quot;/gi,'"')
  .replace(/&#39;|&apos;/gi,"'").replace(/&#(x[0-9a-f]+|\d+);/gi,(entity,code)=>{
   const point=code[0].toLowerCase()==='x'?Number.parseInt(code.slice(1),16):Number.parseInt(code,10);
   return point<=0x10ffff&&!(point>=0xd800&&point<=0xdfff)?String.fromCodePoint(point):entity;
  }).replace(/\s+/g,' ').trim();
}

function descriptionFromPost(html){
 const match=html.match(/<td\b[^>]*data-i18n=["']postDetails\.description["'][^>]*>[\s\S]*?<\/td>\s*<td\b[^>]*>([\s\S]*?)<\/td>/i);
 if(!match)return null;
 const description=htmlText(match[1]);
 return !description||/^(?:n\/d|n\/a|-)$/i.test(description)?null:description;
}

async function postDescription(id){
 const url=new URL('https://ransomfeed.it/');
 url.searchParams.set('page','post_details');
 url.searchParams.set('id_post',id);
 const response=await fetch(url,{headers:{Accept:'text/html'},signal:AbortSignal.timeout(12000)});
 if(!response.ok)throw Object.assign(new Error(`HTTP ${response.status}`),{kind:response.status===429?'rate':'http',status:response.status});
 return descriptionFromPost(await response.text());
}

async function enrichSiteDescriptions(siteRows,apiRows){
 const apiById=new Map(apiRows.map(row=>[row.source_record_id,row]));
 const pending=siteRows.filter(row=>!row.description&&!apiById.get(row.source_record_id)?.description&&row.source_record_id);
 let next=0;
 const workers=Array.from({length:Math.min(4,pending.length)},async()=>{
  while(next<pending.length){
   const row=pending[next++];
   try{row.description=await postDescription(row.source_record_id)}
   catch(error){console.warn('RansomFeed post description lookup failed.',{id:row.source_record_id,kind:error.kind||'unavailable'})}
  }
 });
 await Promise.all(workers);
 return siteRows;
}

function recordKey(record){
 return record.source_record_id
  ? `id:${record.source_record_id}`
  : `${record.normalized_victim_name}|${record.threat_group||''}|${record.attack_date||record.discovery_date||''}`;
}

function mergeRows(apiRows,siteRows){
 const records=new Map(siteRows.map(row=>[recordKey(row),row]));
 for(const apiRow of apiRows){
  const key=recordKey(apiRow);
  const siteRow=records.get(key);
  if(!siteRow){records.set(key,apiRow);continue}
  const merged={...siteRow,...apiRow};
  for(const [field,value] of Object.entries(siteRow)){
   if((merged[field]==null||merged[field]==='')&&value!=null&&value!=='')merged[field]=value;
  }
  merged.discovery_date=apiRow.discovery_date||siteRow.discovery_date;
  merged.raw_source_data={documented_api:apiRow.raw_source_data,site_search:siteRow.raw_source_data};
  records.set(key,merged);
 }
 return [...records.values()];
}

async function documentedApiSearch(query){
 const url=`https://api.ransomfeed.it/search/${encodeURIComponent(query)}/offset/1000`;
 const data=await getJson(url);
 const xs=arrayResponse(data);
 if(!xs)throw Object.assign(new Error('Unexpected response schema'),{kind:'invalid'});
 return normalizeRows(xs.filter(row=>matchesDocumentedSearch(row,query)));
}

export async function ransomfeedAdapter(query){
 const [apiResult,siteResult]=await Promise.allSettled([documentedApiSearch(query),siteSearch(query)]);
 if(apiResult.status==='rejected'&&siteResult.status==='rejected'){
  const error=siteResult.reason;
  throw Object.assign(new Error('RansomFeed API and site search are unavailable.'),{kind:error.kind||apiResult.reason.kind||'unavailable',status:error.status||apiResult.reason.status});
 }
 if(apiResult.status==='rejected')console.warn('RansomFeed documented API failed; using site-search results.',apiResult.reason.kind||'unavailable');
 if(siteResult.status==='rejected')console.warn('RansomFeed site search failed; using documented API results.',siteResult.reason.kind||'unavailable');
 const apiRows=apiResult.status==='fulfilled'?apiResult.value:[];
 const siteRows=siteResult.status==='fulfilled'?await enrichSiteDescriptions(siteResult.value,apiRows):[];
 return mergeRows(
  apiRows,
  siteRows,
 );
}
