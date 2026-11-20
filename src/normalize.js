export const SOURCES = ['RansomLook', 'RansomFeed', 'Ransomware.live Pro'];
export function cleanText(value) { return typeof value === 'string' && value.trim() ? value.trim() : null; }
export function normalizeName(value) { return (value || '').normalize('NFKC').toLowerCase().replace(/https?:\/\//g, '').replace(/^www\./, '').replace(/[^\p{L}\p{N}]+/gu, ' ').trim().replace(/\s+/g, ' '); }
export function extractDomain(value) {
  if (!value) return null;
  const candidates = [value.match(/(?:https?:\/\/)?(?:www\.)?([\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)/u)?.[1]];
  return candidates[0]?.toLowerCase().replace(/^www\./, '') || null;
}
export function record({victim,website,country,industry,group,attackDate,discoveryDate,publicationDate,lastUpdated,description,screenshot,url,source,id,raw}) {
  const name=cleanText(victim) || 'Not available';
  return {victim_name:name,normalized_victim_name:normalizeName(name),website:cleanText(website),domain:extractDomain(website)||extractDomain(name),country:cleanText(country),industry:cleanText(industry),threat_group:cleanText(group),attack_date:cleanText(attackDate),discovery_date:cleanText(discoveryDate),publication_date:cleanText(publicationDate),last_updated:cleanText(lastUpdated),description:cleanText(description),screenshot_url:cleanText(screenshot),original_record_url:cleanText(url),source_name:source,source_record_id:cleanText(id),raw_source_data:raw};
}
function similarity(a,b){const x=normalizeName(a),y=normalizeName(b);if(!x||!y)return 0;if(x===y)return 1;const prev=Array.from({length:y.length+1},(_,i)=>i);for(let i=1;i<=x.length;i++){let diagonal=prev[0];prev[0]=i;for(let j=1;j<=y.length;j++){const old=prev[j];prev[j]=Math.min(prev[j]+1,prev[j-1]+1,diagonal+(x[i-1]===y[j-1]?0:1));diagonal=old;}}return 1-prev[y.length]/Math.max(x.length,y.length);}
export function matchRecords(records) {
  const clusters=[];
  for(const r of records){let target=null, confidence='unique', possible=false;for(const c of clusters){for(const x of c.records){const sameDomain=r.domain&&x.domain&&r.domain===x.domain;const sim=similarity(r.victim_name,x.victim_name);const sameCountry=r.country&&x.country&&r.country.toLowerCase()===x.country.toLowerCase();const sameGroup=r.threat_group&&x.threat_group&&r.threat_group.toLowerCase()===x.threat_group.toLowerCase();const a=(r.attack_date||r.publication_date||'').slice(0,10),b=(x.attack_date||x.publication_date||'').slice(0,10),sameDate=a&&b&&a===b;const support=sameCountry||sameGroup||sameDate;
        if(sameDomain){target=c;confidence='exact';break;}
        if(sim===1){target=c;confidence='exact';break;}
        if(sim>=.80&&support){target=c;confidence='high';break;}
        if(sim>=.75)possible=true;
      }if(target)break;}
    if(!target){target={records:[],match_status:possible?'possible':'unique'};clusters.push(target);}else if(confidence==='high'&&target.match_status==='unique')target.match_status='high';else if(confidence==='exact')target.match_status='exact';target.records.push(r);
  }
  for(let i=0;i<clusters.length;i++)for(let j=i+1;j<clusters.length;j++)if(!['exact','high'].includes(clusters[i].match_status)&&!['exact','high'].includes(clusters[j].match_status)&&similarity(clusters[i].records[0].victim_name,clusters[j].records[0].victim_name)>=.75){clusters[i].match_status='possible';clusters[j].match_status='possible';}
  return clusters.map(c=>({records:c.records,victim_name:c.records[0].victim_name,sources:[...new Set(c.records.map(r=>r.source_name))],match_status:c.records.length<2?c.match_status:c.match_status,confidence:c.match_status,record_count:c.records.length,domain:c.records.find(r=>r.domain)?.domain,latest_discovery:c.records.map(r=>r.discovery_date).filter(Boolean).sort().at(-1)||null}));
}
