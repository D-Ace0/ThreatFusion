"use strict";
async function send(path,method="GET"){
 const headers={"Content-Type":"application/json"};
 const key=document.getElementById("key").value;if(key)headers["X-API-Key"]=key;
 const output=document.getElementById("response");output.textContent="Request in progress…";
 try{const options={method,headers};if(method==="POST"){const body=document.getElementById("body").value;JSON.parse(body);options.body=body;}const r=await fetch(path,options);output.textContent=`HTTP ${r.status}\n`+JSON.stringify(await r.json(),null,2);}catch(e){output.textContent=e.message;}
}
document.getElementById("health").addEventListener("click",()=>send("/api/health"));
document.getElementById("history").addEventListener("click",()=>send("/api/history"));
document.getElementById("send").addEventListener("click",()=>send("/api/analyze","POST"));
